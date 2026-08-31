//! Configuring and starting the libkrun VM, and serving the control channel
//! that carries the boot plan into the guest.

pub mod boot;
pub mod image;

use self::boot::BootSpec;
use crate::policy::network::rules;
use crate::policy::network::runtime;
use crate::render::{format_mount_lines, format_workload_line, render_redacted_config_yaml};
use crate::state::BoxRef;
use crate::{config, logs, sys};
use anyhow::{Context, Result, bail};
use krun::{
    krun_add_disk, krun_add_net_unixstream, krun_add_virtio_console_default, krun_add_virtiofs3,
    krun_add_vsock, krun_add_vsock_port2, krun_create_ctx, krun_set_kernel, krun_set_vm_config,
    krun_start_enter,
};
use smolvm_network::GuestNetworkConfig;
use std::ffi::CString;
use std::fs::File;
#[cfg(unix)]
use std::io::Read as _;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::path::Path;
use std::process::ExitCode;
use terra_shared::contract::{
    AGENT_VSOCK_PORT, CONTROL_VSOCK_PORT, Disk, KERNEL_CMDLINE, Net, Plan, PlanMode, Share,
    WORKLOAD_ID, WORKLOAD_USER_NAME, encode_frame, read_frame, to_volume_device,
};

const NET_FEATURES: u32 = 0;
const DIAGNOSTICS_ENV_VAR: &str = "TERRA_DIAGNOSTICS";
// libkrunfw emits ELF on x86_64 and a raw Image on aarch64.
#[cfg(target_arch = "x86_64")]
const KERNEL_FORMAT: u32 = 1;
#[cfg(target_arch = "aarch64")]
const KERNEL_FORMAT: u32 = 0;

fn convert_to_c_path(path: &Path) -> Result<CString> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.contains(&0) {
        anyhow::bail!("path contains a NUL byte: {}", path.display());
    }
    Ok(CString::new(bytes)?)
}

#[allow(unsafe_code)]
fn configure_context(cfg: &config::Config) -> Result<u32> {
    let ctx_id = krun_create_ctx();
    if ctx_id < 0 {
        bail!(
            "krun_create_ctx failed: {} ({ctx_id})",
            std::io::Error::from_raw_os_error(-ctx_id)
        );
    }
    let ctx_id = ctx_id.cast_unsigned();
    let rc = krun_set_vm_config(ctx_id, cfg.hw.cpus, cfg.hw.mem_mib);
    if rc < 0 {
        bail!(
            "krun_set_vm_config failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }
    let kernel = convert_to_c_path(&image::ensure_kernel_on_disk()?)?;
    let cmdline = CString::new(KERNEL_CMDLINE)?;
    let rc = unsafe {
        krun_set_kernel(
            ctx_id,
            kernel.as_ptr(),
            KERNEL_FORMAT,
            std::ptr::null(),
            cmdline.as_ptr(),
        )
    };
    if rc < 0 {
        bail!(
            "krun_set_kernel failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }
    Ok(ctx_id)
}

// The two VMs one spec can ask for, told apart by `spec.mode`:
//   Create - a bare VM that bakes `on_create` and stops. No shares and no
//            agent ports, so nothing on the host is reachable from the guest.
//   Run    - the workload boot: shares mounted, agent ports served, runs
//            until stopped.

pub(crate) const GUEST_NETWORK: GuestNetworkConfig = GuestNetworkConfig::default();

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

/// Attach the box's block devices. The kernel cmdline and the boot plan name
/// the devices this produces, so the add order *is* the contract:
///   /dev/vda  boot volume (agent + resize2fs, read-only, roots the kernel)
///   /dev/vdb  the box's persistent root filesystem
///   /dev/vdc… one per configured volume
#[allow(unsafe_code)]
fn attach_disks(ctx_id: u32, cfg: &config::Config, bx: &BoxRef) -> Result<Vec<Disk>> {
    let boot = image::ensure_boot_volume_on_disk()?;
    let root = bx.get_dir().join(crate::state::ROOTFS_FILE);
    for (id, path, read_only) in [
        ("terra-boot", boot.as_path(), true),
        ("terra-root", root.as_path(), false),
    ] {
        let id = CString::new(id)?;
        let path = convert_to_c_path(path)?;
        let rc = unsafe { krun_add_disk(ctx_id, id.as_ptr(), path.as_ptr(), read_only) };
        if rc < 0 {
            bail!(
                "krun_add_disk for {} failed: {} ({rc})",
                path.to_string_lossy(),
                std::io::Error::from_raw_os_error(-rc)
            );
        }
    }
    let mut volumes = Vec::new();
    for (i, v) in cfg.volumes.iter().enumerate() {
        let img = bx.get_volume_image(&v.name);
        image::ensure_volume_image(&img, v.size_mib)
            .with_context(|| format!("preparing volume image {}", img.display()))?;
        let id = CString::new(format!("vol{i}"))?;
        let path = convert_to_c_path(&img)?;
        let rc = unsafe { krun_add_disk(ctx_id, id.as_ptr(), path.as_ptr(), false) };
        if rc < 0 {
            bail!(
                "krun_add_disk for {} failed: {} ({rc})",
                img.display(),
                std::io::Error::from_raw_os_error(-rc)
            );
        }
        volumes.push(Disk {
            // Recipe validation caps volumes at MAX_VOLUMES, so this is a bug
            // guard, not an input check.
            dev: to_volume_device(i)
                .with_context(|| format!("volume {i} is past the last guest block device"))?,
            guest: v.guest.to_string_lossy().into_owned(),
        });
    }
    Ok(volumes)
}

#[allow(unsafe_code)]
fn attach_shares(
    ctx_id: u32,
    cfg: &config::Config,
    bx: &BoxRef,
    mode: PlanMode,
) -> Result<Vec<Share>> {
    if mode != PlanMode::Run {
        return Ok(Vec::new());
    }

    let mounts = crate::policy::mount::resolve_mounts(cfg, bx)?;
    let mut shares = Vec::with_capacity(mounts.len());
    for (i, m) in mounts.iter().enumerate() {
        let tag = format!("sh{i}");
        let tag_c = CString::new(tag.as_str())?;
        let path = convert_to_c_path(&m.host)?;
        let rc = unsafe {
            const VIRTIOFS_DAX_WINDOW: u64 = 1 << 29;
            krun_add_virtiofs3(
                ctx_id,
                tag_c.as_ptr(),
                path.as_ptr(),
                VIRTIOFS_DAX_WINDOW,
                m.readonly,
            )
        };
        if rc < 0 {
            bail!(
                "krun_add_virtiofs3 for {} failed: {} ({rc})",
                m.host.display(),
                std::io::Error::from_raw_os_error(-rc)
            );
        }
        shares.push(Share {
            tag,
            guest: m.guest.to_string_lossy().into_owned(),
            readonly: m.readonly,
        });
    }
    Ok(shares)
}

/// libkrun binds under the process umask; the `0700` state directory is what
/// keeps another account off the root-capable exec service behind it.
#[allow(unsafe_code)]
fn attach_agent_port(ctx_id: u32, bx: &BoxRef) -> Result<()> {
    let path = bx.get_dir().join(crate::state::AGENT_SOCKET);
    // A crashed prior VM may have left a socket; libkrun binds EEXIST.
    let _ = std::fs::remove_file(&path);
    image::sweep_staging_temps(bx.get_dir(), |_| false);
    let path = convert_to_c_path(&path)?;
    let rc = unsafe { krun_add_vsock_port2(ctx_id, AGENT_VSOCK_PORT, path.as_ptr(), true) };
    if rc < 0 {
        bail!(
            "krun_add_vsock_port2 failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }
    Ok(())
}

#[allow(unsafe_code)]
pub fn run(spec: &BootSpec, bx: &BoxRef, lock: &File) -> Result<ExitCode> {
    // Before libkrun exists to log anything.
    logs::init(bx)?;
    let cfg = &spec.cfg;
    let mode = spec.mode;
    if mode == PlanMode::Run {
        // Only a Run VM attaches shares (see the mode notes above), so only it
        // can hand a writable one to host root - checked here because this
        // process, not the spawning parent, is the one that attaches them.
        validate_root_writable_shares(cfg)?;
        // Registered before the pid is published, so no SIGTERM can land where
        // it would kill the process outright, `pre_stop` and all.
        sys::install_stop_signal_handlers();
    }
    let ctx_id = configure_context(cfg)?;

    let volumes = attach_disks(ctx_id, cfg, bx)?;
    let shares = attach_shares(ctx_id, cfg, bx, mode)?;

    let null = sys::open_null().context("opening the null device for the guest console")?;
    let diag = std::env::var_os(DIAGNOSTICS_ENV_VAR)
        .is_some_and(|v| v == "1")
        .then(|| {
            let path = bx.get_dir().join(crate::state::DIAGNOSTICS_LOG);
            sys::create_no_symlinks(&path).with_context(|| format!("opening {}", path.display()))
        })
        .transpose()?;
    let console_output = open_console_file(spec, bx, diag.as_ref())?;
    let rc = unsafe {
        krun_add_virtio_console_default(
            ctx_id,
            null.as_raw_fd(),
            console_output.as_raw_fd(),
            console_output.as_raw_fd(),
        )
    };
    if rc < 0 {
        bail!(
            "krun_add_virtio_console_default failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }
    let _console = (null, console_output);

    let _net_rt = start_networking(ctx_id, &cfg.network)?;
    // The vsock device carries every port added after it.
    let rc = krun_add_vsock(ctx_id, 0);
    if rc < 0 {
        bail!(
            "krun_add_vsock failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }

    if mode == PlanMode::Run {
        attach_agent_port(ctx_id, bx)?;
    }

    let plan = build_plan(spec, shares, volumes);
    serve_control_sock(ctx_id, bx, &plan)?;
    bx.publish_pid(lock, std::process::id(), mode == PlanMode::Create);

    let (vcpus, mem) = (cfg.hw.cpus, cfg.hw.mem_mib);
    match plan.mode {
        PlanMode::Create => {
            log::info!("terra: baking on_create for {bx} ({vcpus} vCPU, {mem} MiB)");
        }
        PlanMode::Run => {
            log::info!("terra: starting {bx} ({vcpus} vCPU, {mem} MiB)");
            for line in format_mount_lines(cfg) {
                log::info!("{line}");
            }
        }
    }

    // Anything that still writes straight to stdout/stderr - a panic, a
    // foreign library - belongs to diagnostics, not to the terminal.
    if let Some(diag) = diag {
        sys::point_stdio_at(&diag).with_context(|| {
            format!(
                "redirecting stray output into {}",
                bx.get_dir().join(crate::state::DIAGNOSTICS_LOG).display()
            )
        })?;
    }

    let rc = krun_start_enter(ctx_id);
    if rc < 0 {
        bail!(
            "krun_start_enter failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }

    // Not reached in practice - a finished box has already left through
    // the guest exits through its own status, a dead one through libkrun's own exit.
    Ok(ExitCode::SUCCESS)
}

/// The resolved config the agent runs as PID 1.
fn build_plan(spec: &BootSpec, shares: Vec<Share>, volumes: Vec<Disk>) -> Plan {
    let cfg = &spec.cfg;
    let net = GUEST_NETWORK;
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
        share_owner: sys::read_share_owner(),
        net: Net {
            guest_ip: net.guest_ip.into(),
            prefix: net.prefix_len,
            gateway: net.gateway_ip.into(),
            dns: net.dns_server.into(),
        },
        env: cfg.env.clone(),
        root: spec.root || baking,
        sudo: cfg.sudo.clone(),
        on_create: cfg.hooks.on_create.clone(),
        on_start: cfg.hooks.on_start.clone(),
        pre_stop: cfg.hooks.pre_stop.clone(),
        daemons: cfg.daemons.clone(),
        workload_on_console: spec.foreground,
        workload: std::iter::once(cfg.workload.entrypoint.to_string_lossy().into_owned())
            .chain(cfg.workload.args.iter().cloned())
            .collect(),
        sandbox_info: generate_sandbox_info(cfg, spec.root),
        host_tz: read_host_timezone(),
    }
}

/// Where the guest console writes for this boot: whoever is listening.
fn open_console_file(spec: &BootSpec, bx: &BoxRef, diag: Option<&File>) -> Result<File> {
    if spec.foreground {
        use std::os::fd::AsFd;
        return std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map(File::from)
            .context("duplicating stdout for the guest console");
    }
    if let Some(f) = diag {
        return f
            .try_clone()
            .context("duplicating the diagnostics log for the guest console");
    }
    if spec.mode == PlanMode::Create {
        // O_APPEND on the symlink's target: a bake outlives no rotation.
        return std::fs::OpenOptions::new()
            .append(true)
            .open(bx.get_dir().join(crate::state::LOG_FILE))
            .with_context(|| {
                format!(
                    "appending the bake console to {}",
                    bx.get_dir().join(crate::state::LOG_FILE).display()
                )
            });
    }
    sys::open_null().context("opening the null device for the guest console")
}

/// What the agent writes to `/terra/README.md`, so an AI agent looking
/// around the box finds an explanation instead of guessing.
#[must_use]
fn generate_sandbox_info(cfg: &config::Config, root: bool) -> String {
    let net = GUEST_NETWORK;
    let yaml = render_redacted_config_yaml(cfg).unwrap_or_default();
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
        egress = runtime::describe(&cfg.network),
        ip = net.guest_ip,
        prefix = net.prefix_len,
        gw = net.gateway_ip,
        dns = net.dns_server,
    )
}

/// The guest's traffic terminates in-process, under the egress policy. Keep
/// the returned runtime alive for the VM's life.
#[must_use = "the VM's networking dies with this runtime"]
#[allow(unsafe_code)]
fn start_networking(
    ctx_id: u32,
    net: &config::Network,
) -> Result<smolvm_network::VirtioNetworkRuntime> {
    let guest_net = GUEST_NETWORK;
    let (host_end, krun_end) =
        std::os::unix::net::UnixStream::pair().context("creating virtio-net socketpair")?;
    let krun_fd = krun_end.into_raw_fd();
    let rc = unsafe {
        krun_add_net_unixstream(
            ctx_id,
            std::ptr::null(),
            krun_fd,
            guest_net.guest_mac.as_ptr(),
            NET_FEATURES,
            0,
        )
    };
    if rc < 0 {
        unsafe { libc::close(krun_fd) };
        bail!(
            "krun_add_net_unixstream failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }
    let egress = runtime::BoxPolicy::new(net)?;
    log::info!(
        "terra: egress: {} - loopback/LAN/private/CGNAT floored unless a rule names them",
        runtime::describe(net)
    );
    let ports = rules::parse_port_mappings(&net.ports)?;
    for p in &ports {
        log::info!(
            "terra: published: 127.0.0.1:{} -> guest:{}",
            p.host,
            p.guest
        );
    }
    smolvm_network::start_virtio_network(
        std::os::fd::OwnedFd::from(host_end).into(),
        guest_net,
        &ports,
        egress,
        None,
    )
    .context("starting host-side virtio-net runtime")
}

/// Opt-out for the host-root refusal below - an env var, not a flag, so it
/// cannot creep into an alias.
const ALLOW_ROOT_ENV: &str = "TERRA_ALLOW_ROOT";

fn validate_root_writable_shares(cfg: &config::Config) -> Result<()> {
    if sys::is_host_root() && cfg.mounts.iter().any(|m| !m.readonly) {
        anyhow::ensure!(
            std::env::var_os(ALLOW_ROOT_ENV).is_some_and(|v| v == "1"),
            "running as host root, the guest writes read-write shares as real root - \
             a sandbox escape is a `chmod u+s` away.\n\
             Run terra as an unprivileged user in the `kvm` group (see \
             packaging/README.md), mark the mounts `readonly: true`, or set \
             {ALLOW_ROOT_ENV}=1 to proceed anyway"
        );
        log::warn!(
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
#[allow(unsafe_code)]
fn serve_control_sock(ctx_id: u32, bx: &BoxRef, plan: &Plan) -> Result<()> {
    let watch_stop = plan.mode == PlanMode::Run;
    let sock = bx.get_dir().join(crate::state::CONTROL_SOCKET);
    let _ = std::fs::remove_file(&sock); // a crashed prior VM may have left one
    image::sweep_staging_temps(bx.get_dir(), |_| false);
    let listener = std::os::unix::net::UnixListener::bind(&sock)
        .with_context(|| format!("binding the control socket {}", sock.display()))?;
    // `bind` applies the process umask; the socket hands out secrets, so the
    // mode is stated here too, not left to the state dir alone.
    sys::set_owner_only(&sock, false).with_context(|| format!("securing {}", sock.display()))?;
    let path = convert_to_c_path(&sock)?;
    let rc = unsafe { krun_add_vsock_port2(ctx_id, CONTROL_VSOCK_PORT, path.as_ptr(), false) };
    if rc < 0 {
        bail!(
            "krun_add_vsock_port2 failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }

    let frame = encode_frame(plan).context("serializing the boot plan")?;
    std::thread::spawn(move || {
        use std::io::Write;
        let accepted = listener.accept();
        // Stop listening the moment the agent has dialed: a later dial from
        // inside the guest gets a refused connection, not the plan.
        drop(listener);
        let mut conn = match accepted {
            Ok((conn, _)) => conn,
            Err(e) => {
                log::warn!("terra: warning: the guest never opened the control port: {e}");
                return;
            }
        };
        if let Err(e) = conn.write_all(&frame) {
            log::warn!("terra: warning: could not send the boot plan: {e}");
            return;
        }
        if watch_stop {
            match conn.try_clone() {
                Ok(stop_channel) => sys::register_stop_channel(stop_channel.into()),
                Err(e) => log::warn!(
                    "terra: warning: no stop channel for this box ({e}) - \
                     it can only be killed"
                ),
            }
        }
        // Park on the connection instead of closing it: closing while
        // `pre_stop` runs would cut the stop channel out from under the guest.
        // The guest's last act on it is its exit status; a read that ends
        // without one is the VM dying rather than finishing.
        if let Ok(Some(code)) = read_frame::<i32>(&mut conn) {
            std::process::exit(i32::from(crate::exit_status_byte(code)));
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

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
        let plan = build_plan(&spec, shares, volumes);

        assert_eq!(plan.workload, ["/bin/sh", "-c", "make"]);
        assert_eq!(plan.daemons, ["ascend --serve"]);
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
            build_plan(&foreground, vec![], vec![]).workload_on_console,
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
            cfg: yaml_serde::from_str("{}").unwrap(),
            project_dir: PathBuf::from("/proj"),
            root,
            mode,
            foreground: false,
        };
        let plan = |root, mode| build_plan(&spec(root, mode), vec![], vec![]).root;

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

    #[cfg(unix)]
    #[test]
    fn c_paths_accept_non_utf8_os_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(b"/tmp/project-\x80".to_vec()));
        assert_eq!(
            convert_to_c_path(&path).unwrap().as_bytes(),
            b"/tmp/project-\x80"
        );
    }
}
