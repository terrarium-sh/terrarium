use anyhow::{Context, Result, bail};
use rustix::mount::{MountFlags, MountPropagationFlags};
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use terra_protocol::{CLOCK_SYNC, CLOCK_SYNC_BYTES, Plan, RESIZE2FS_GUEST_PATH, ROOT_DEVICE};

const CLEAN_MOUNT: &str = "/mnt/clean";
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub(super) struct Boot {
    pub(super) plan: Plan,
    pub(super) control: File,
    pub(super) diagnostic: File,
    pub(super) clients: tokio::sync::mpsc::Receiver<File>,
    pub(super) mux: crate::mux::GuestMux,
}

pub(super) fn enter_root() -> Result<Boot> {
    const NEWROOT: &str = "/mnt/root";

    mount(None, "/proc", Some("proc"), MountFlags::empty()).context("mounting /proc")?;
    mount(None, "/sys", Some("sysfs"), MountFlags::empty()).context("mounting /sys")?;
    fs::set_permissions("/dev/net/tun", fs::Permissions::from_mode(0o666))
        .context("enabling rootless guest networking on /dev/net/tun")?;
    fs::create_dir_all("/dev/pts")?;
    mount(None, "/dev/pts", Some("devpts"), MountFlags::empty()).context("mounting /dev/pts")?;
    fs::create_dir_all("/dev/shm")?;
    for (target, fstype) in [("/dev/shm", "tmpfs"), ("/sys/fs/cgroup", "cgroup2")] {
        if let Err(e) = mount(None, target, Some(fstype), MountFlags::empty()) {
            eprintln!("terra-agent: warning: could not mount {target}: {e:#}");
        }
    }
    mount(None, "/mnt", Some("tmpfs"), MountFlags::empty())
        .context("mounting the staging tmpfs")?;
    fs::create_dir_all(NEWROOT)?;
    fs::create_dir_all(CLEAN_MOUNT)?;

    let crate::mux::Streams {
        mut control,
        diagnostic,
        clients,
        driver: mux,
    } = crate::mux::GuestMux::connect()?;
    let plan: Plan =
        terra_protocol::read_frame_with_limit(&mut control, terra_protocol::MAX_PLAN_BYTES)
            .context("reading the boot plan")?
            .ok_or_else(|| anyhow::anyhow!("control channel closed before receiving boot plan"))?;
    setup_env(&plan);
    apply_host_state(&plan)?;
    grow_filesystem(ROOT_DEVICE);
    for volume in &plan.volumes {
        grow_filesystem(&volume.dev);
    }
    mount(
        Some(ROOT_DEVICE),
        NEWROOT,
        Some("ext4"),
        MountFlags::empty(),
    )
    .with_context(|| format!("mounting the guest rootfs image ({ROOT_DEVICE})"))?;
    for directory in ["proc", "sys", "dev", "terra"] {
        fs::create_dir_all(format!("{NEWROOT}/{directory}"))?;
    }
    for directory in ["proc", "sys", "dev"] {
        let source = format!("/{directory}");
        let target = format!("{NEWROOT}/{directory}");
        mount(
            Some(&source),
            &target,
            None,
            MountFlags::BIND | MountFlags::REC,
        )
        .with_context(|| format!("binding /{directory} into the guest root"))?;
    }
    std::env::set_current_dir(NEWROOT).context("entering the guest root")?;
    rustix::process::pivot_root(".", ".").context("switching to the guest root")?;
    rustix::mount::unmount(".", rustix::mount::UnmountFlags::DETACH)
        .context("detaching the boot root")?;
    std::env::set_current_dir("/").context("chdir after pivot_root")?;
    rustix::mount::mount_change(
        "/",
        MountPropagationFlags::SHARED | MountPropagationFlags::REC,
    )
    .context("making guest mounts shared for rootless containers")?;
    fs::create_dir_all("/run")?;
    mount(
        None,
        "/run",
        Some("tmpfs"),
        MountFlags::NOSUID | MountFlags::NODEV,
    )?;
    fs::set_permissions("/run", fs::Permissions::from_mode(0o755))?;
    apply_tz(plan.host_tz.as_deref());
    Ok(Boot {
        plan,
        control,
        diagnostic,
        clients,
        mux,
    })
}

fn grow_filesystem(device: &str) {
    if let Err(error) = mount(Some(device), CLEAN_MOUNT, Some("ext4"), MountFlags::empty()) {
        eprintln!("terra-agent: warning: {device} would not mount ({error:#}) - skipping resize");
        return;
    }
    if let Err(error) = rustix::mount::unmount(CLEAN_MOUNT, rustix::mount::UnmountFlags::empty())
        .map_err(std::io::Error::from)
        .with_context(|| format!("umount {CLEAN_MOUNT}"))
    {
        eprintln!(
            "terra-agent: warning: could not unmount {CLEAN_MOUNT} ({error:#}) - skipping resize"
        );
        let _ = rustix::mount::unmount(CLEAN_MOUNT, rustix::mount::UnmountFlags::DETACH);
        return;
    }
    match Command::new(RESIZE2FS_GUEST_PATH)
        .args(["-f", device])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!(
            "terra-agent: warning: resize2fs {device} exited {status} - image may be undersized"
        ),
        Err(error) => {
            eprintln!("terra-agent: warning: could not run resize2fs for {device}: {error}");
        }
    }
}

fn apply_tz(bytes: Option<&[u8]>) {
    if let Some(bytes) = bytes.filter(|bytes| !bytes.is_empty()) {
        let _ = fs::create_dir_all("/etc");
        let tmp = "/etc/.localtime.tmp";
        if let Err(error) = fs::write(tmp, bytes) {
            eprintln!("terra-agent: warning: could not write /etc/localtime: {error}");
        } else {
            let _ = fs::rename(tmp, "/etc/localtime");
        }
    }
}

fn apply_host_state(plan: &Plan) -> Result<()> {
    if let Some(seed) = plan.host_seed {
        credit_entropy(&seed)?;
        let mut ready = [0];
        rustix::rand::getrandom(&mut ready, rustix::rand::GetRandomFlags::empty())
            .context("waiting for the guest CSPRNG")?;
    }
    if let Some(time) = plan.host_time {
        synchronize_clock(time.seconds, time.nanoseconds, true)?;
    }
    Ok(())
}

#[repr(C)]
struct EntropyCredit {
    entropy_bits: i32,
    byte_count: i32,
    bytes: [u8; 32],
}

#[allow(unsafe_code)]
fn credit_entropy(seed: &[u8; 32]) -> Result<()> {
    let random = fs::OpenOptions::new()
        .write(true)
        .open("/dev/random")
        .context("opening the guest entropy device")?;
    let credit = EntropyCredit {
        entropy_bits: 256,
        byte_count: 32,
        bytes: *seed,
    };
    // SAFETY: RNDADDENTROPY reads this exact C layout and all 32 bytes are a fresh trusted WASI secure-random seed, so crediting 256 bits is sound.
    let request =
        unsafe { rustix::ioctl::Setter::<{ linux_raw_sys::ioctl::RNDADDENTROPY }, _>::new(credit) };
    // SAFETY: `/dev/random` implements RNDADDENTROPY and `request` owns the matching input buffer for the call.
    unsafe { rustix::ioctl::ioctl(&random, request) }
        .map_err(std::io::Error::from)
        .context("crediting the guest CSPRNG")?;
    Ok(())
}

pub(super) fn synchronize_clock(seconds: i64, nanoseconds: u32, bootstrap: bool) -> Result<()> {
    if nanoseconds >= 1_000_000_000 {
        bail!("invalid host clock sample");
    }
    let current = rustix::time::clock_gettime(rustix::time::ClockId::Realtime);
    if !bootstrap && current.tv_sec.abs_diff(seconds) < 5 {
        return Ok(());
    }
    rustix::time::clock_settime(
        rustix::time::ClockId::Realtime,
        rustix::time::Timespec {
            tv_sec: seconds,
            tv_nsec: nanoseconds.into(),
        },
    )
    .map_err(std::io::Error::from)
    .context("synchronizing the guest clock")?;
    Ok(())
}

pub(super) async fn read_clock_update(reader: &mut crate::AsyncFile) -> Result<()> {
    use tokio::io::AsyncReadExt as _;
    let mut bytes = [0; CLOCK_SYNC_BYTES];
    bytes[0] = CLOCK_SYNC;
    reader
        .read_exact(&mut bytes[1..])
        .await
        .context("reading clock update")?;
    let (seconds, nanoseconds) = terra_protocol::decode_clock_sync(&bytes)
        .ok_or_else(|| anyhow::anyhow!("invalid clock update"))?;
    synchronize_clock(seconds, nanoseconds, false)
}

pub(super) fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: MountFlags,
) -> Result<()> {
    rustix::mount::mount(
        source.unwrap_or("none"),
        target,
        fstype.unwrap_or("none"),
        flags,
        if fstype == Some("ext4") && !flags.contains(MountFlags::RDONLY) {
            c"discard"
        } else {
            c""
        },
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("mounting {target}"))
}

#[allow(unsafe_code)]
fn setup_env(plan: &Plan) {
    // SAFETY: no other thread touches the environment yet.
    unsafe {
        std::env::set_var("PATH", DEFAULT_PATH);
        std::env::set_var("TERM", "xterm-256color");
        for (key, value) in &plan.env {
            if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
                eprintln!("terra-agent: warning: skipping invalid env key `{key}`");
                continue;
            }
            std::env::set_var(key, value);
        }
        std::env::set_var("HOME", terra_protocol::WORKLOAD_HOME);
        std::env::set_var(
            "XDG_RUNTIME_DIR",
            format!("/run/user/{}", terra_protocol::WORKLOAD_ID),
        );
    }
    let _ = rustix::system::sethostname(b"terrarium");
}

#[cfg(test)]
mod tests {
    use super::*;
    use terra_protocol::{Net, Plan, PlanMode};
    #[test]
    fn setup_env_allows_plan_to_override_path_and_term_while_preserving_home() {
        const CHILD: &str = "TERRA_TEST_SETUP_ENV_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "bootstrap::tests::setup_env_allows_plan_to_override_path_and_term_while_preserving_home", "--test-threads=1"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let inherited_path = std::env::var("PATH").ok();
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "PATH".to_string(),
            format!(
                "/custom/bin:{}",
                inherited_path.as_deref().unwrap_or(DEFAULT_PATH)
            ),
        );
        env.insert("TERM".to_string(), "custom-term".to_string());
        env.insert("HOME".to_string(), "/attempted/home".to_string());
        let plan = Plan {
            mode: PlanMode::Run,
            workdir: None,
            shares: Vec::new(),
            volumes: Vec::new(),
            net: Net {
                guest_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 15)),
                prefix: 24,
                gateway: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 2)),
                dns: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 2, 3)),
            },
            env,
            root: false,
            sudo: Vec::new(),
            on_create: Vec::new(),
            on_start: Vec::new(),
            pre_stop: Vec::new(),
            daemons: Vec::new(),
            workload: Vec::new(),
            sandbox_info: String::new(),
            await_initial_session: false,
            host_tz: None,
            host_time: None,
            host_seed: None,
        };
        setup_env(&plan);
        assert!(std::env::var("PATH").unwrap().starts_with("/custom/bin:"));
        assert_eq!(std::env::var("TERM").unwrap(), "custom-term");
        assert_eq!(
            std::env::var("HOME").unwrap(),
            terra_protocol::WORKLOAD_HOME
        );
    }
}
