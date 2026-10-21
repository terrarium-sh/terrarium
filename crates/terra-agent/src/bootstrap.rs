use anyhow::{Context, Result, bail};
use rustix::mount::{MountFlags, MountPropagationFlags};
use std::fs::{self, File};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::FileExt;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use terra_protocol::{
    BootPlan, CLOCK_SYNC, CLOCK_SYNC_BYTES, Plan, RESIZE2FS_GUEST_PATH, ROOT_DEVICE,
};

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
    let plan = read_boot_plan(&mut control)?;
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

fn read_boot_plan(reader: &mut impl std::io::Read) -> Result<Plan> {
    let boot_plan: BootPlan =
        terra_protocol::read_frame_with_limit(reader, terra_protocol::MAX_PLAN_BYTES)
            .context("reading the boot plan")?
            .ok_or_else(|| anyhow::anyhow!("control channel closed before receiving boot plan"))?;
    boot_plan
        .validate_protocol_versions()
        .context("validating boot protocol versions")?;
    boot_plan
        .plan
        .validate_network()
        .context("validating guest network configuration")?;
    Ok(boot_plan.plan)
}

const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_LEN: usize = 1024;
const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_MAX_LOG_BLOCK_SIZE: u32 = 6;
const SB_BLOCKS_COUNT_LO: usize = 0x04;
const SB_LOG_BLOCK_SIZE: usize = 0x18;
const SB_MAGIC: usize = 0x38;
const SB_FEATURE_INCOMPAT: usize = 0x60;
const SB_FEATURE_RO_COMPAT: usize = 0x64;
const SB_BLOCKS_COUNT_HI: usize = 0x150;
const INCOMPAT_64BIT: u32 = 0x80;
const RO_COMPAT_BIGALLOC: u32 = 0x200;

/// Whether the ext4 superblock of `device` already counts as many blocks as resize2fs would
/// resize to; any doubt answers `false`.
fn filesystem_already_spans_device(device: &str) -> bool {
    read_superblock(device).is_ok_and(|(superblock, device_bytes)| {
        superblock_spans_device(&superblock, device_bytes, rustix::param::page_size() as u64)
    })
}

fn read_superblock(device: &str) -> std::io::Result<(Vec<u8>, u64)> {
    let mut file = File::open(device)?;
    let device_bytes = file.seek(SeekFrom::End(0))?;
    let mut superblock = vec![0; SUPERBLOCK_LEN];
    file.read_exact_at(&mut superblock, SUPERBLOCK_OFFSET)?;
    Ok((superblock, device_bytes))
}

/// Mirrors resize2fs's default target size (the device rounded down to a page),
/// skipping its group-trimming adjustment: unequal sizes fall back to resizing.
/// A journal awaiting replay cannot change a count that already fills the device:
/// ext4 grows online only up to its device and never shrinks online.
fn superblock_spans_device(superblock: &[u8], device_bytes: u64, page_size: u64) -> bool {
    parse_superblock_span(superblock, device_bytes, page_size).unwrap_or(false)
}

fn parse_superblock_span(superblock: &[u8], device_bytes: u64, page_size: u64) -> Option<bool> {
    let word = |offset: usize| -> Option<u32> {
        let bytes = superblock.get(offset..offset + 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    };
    let magic = superblock.get(SB_MAGIC..SB_MAGIC + 2)?;
    if u16::from_le_bytes(magic.try_into().ok()?) != EXT4_MAGIC {
        return Some(false);
    }
    let incompat = word(SB_FEATURE_INCOMPAT)?;
    if word(SB_FEATURE_RO_COMPAT)? & RO_COMPAT_BIGALLOC != 0 {
        return Some(false);
    }
    let log_block_size = word(SB_LOG_BLOCK_SIZE)?;
    if log_block_size > EXT4_MAX_LOG_BLOCK_SIZE {
        return Some(false);
    }
    let block_size = 1024u64 << log_block_size;
    let mut blocks = u64::from(word(SB_BLOCKS_COUNT_LO)?);
    if incompat & INCOMPAT_64BIT != 0 {
        blocks |= u64::from(word(SB_BLOCKS_COUNT_HI)?) << 32;
    }
    let mut device_blocks = device_bytes / block_size;
    if page_size > block_size {
        device_blocks &= !(page_size / block_size - 1);
    }
    Some(device_blocks == blocks)
}

/// Remounts the volumes and the root read-only so the next boot mounts them without a
/// journal replay; a filesystem a process still writes to stays as it is.
pub(super) fn leave_filesystems_clean(plan: &Plan) {
    for volume in &plan.volumes {
        let _ = rustix::mount::mount_remount(
            volume.guest.as_str(),
            crate::config::VOLUME_MOUNT_FLAGS | MountFlags::RDONLY,
            "",
        );
    }
    let _ = rustix::mount::mount_remount("/", MountFlags::RDONLY, "");
}

fn grow_filesystem(device: &str) {
    if filesystem_already_spans_device(device) {
        return;
    }
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
    let _ = rustix::system::sethostname(plan.hostname.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use terra_protocol::Plan;

    const PAGE: u64 = 4096;

    fn superblock(blocks: u64, log_block_size: u32, incompat: u32, ro_compat: u32) -> Vec<u8> {
        let mut sb = vec![0; SUPERBLOCK_LEN];
        let mut put =
            |offset: usize, value: &[u8]| sb[offset..offset + value.len()].copy_from_slice(value);
        put(0x04, &blocks.to_le_bytes()[..4]);
        put(0x18, &log_block_size.to_le_bytes());
        put(0x38, &EXT4_MAGIC.to_le_bytes());
        put(0x60, &incompat.to_le_bytes());
        put(0x64, &ro_compat.to_le_bytes());
        put(0x150, &blocks.to_le_bytes()[4..8]);
        sb
    }

    #[test]
    fn exact_size_match_skips_resize() {
        assert!(superblock_spans_device(
            &superblock(4096, 2, 0, 0),
            4096 * 4096,
            PAGE
        ));
    }

    #[test]
    fn larger_device_needs_resize() {
        assert!(!superblock_spans_device(
            &superblock(4096, 2, 0, 0),
            8192 * 4096,
            PAGE
        ));
    }

    #[test]
    fn device_size_is_rounded_down_to_a_page_for_small_blocks() {
        let sb = superblock(4096, 0, 0, 0);
        let device_bytes = 4096 * 1024 + 3 * 1024;
        assert!(superblock_spans_device(&sb, device_bytes, PAGE));
        assert!(!superblock_spans_device(&sb, device_bytes + 4096, PAGE));
    }

    #[test]
    fn sixty_four_bit_filesystems_use_the_high_block_count() {
        let blocks = (1u64 << 32) + 8;
        let sb = superblock(blocks, 2, INCOMPAT_64BIT, 0);
        assert!(superblock_spans_device(&sb, blocks * 4096, PAGE));
        assert!(!superblock_spans_device(&sb, 8 * 4096, PAGE));
    }

    /// Every boot after a poweroff without a clean unmount finds the journal flagged for
    /// replay; a filesystem that already fills its device still skips the resize.
    #[test]
    fn journal_awaiting_replay_still_skips_a_filled_device() {
        const INCOMPAT_RECOVER: u32 = 0x4;
        let sb = superblock(4096, 2, INCOMPAT_RECOVER, 0);
        assert!(superblock_spans_device(&sb, 4096 * 4096, PAGE));
        assert!(!superblock_spans_device(&sb, 8192 * 4096, PAGE));
    }

    /// A garbage block-size exponent would wrap `1024 << n` to zero and divide PID 1 by it.
    #[test]
    fn block_size_beyond_ext4s_maximum_needs_resize() {
        for log_block_size in [7, 54, 63, u32::MAX] {
            assert!(!superblock_spans_device(
                &superblock(0, log_block_size, 0, 0),
                4096 * 4096,
                PAGE
            ));
        }
    }

    #[test]
    fn bigalloc_and_bad_magic_need_resize() {
        let size = 4096 * 4096;
        assert!(!superblock_spans_device(
            &superblock(4096, 2, 0, RO_COMPAT_BIGALLOC),
            size,
            PAGE
        ));
        let mut sb = superblock(4096, 2, 0, 0);
        sb[0x38] = 0;
        assert!(!superblock_spans_device(&sb, size, PAGE));
    }

    #[test]
    fn truncated_superblock_needs_resize() {
        let sb = superblock(4096, 2, 0, 0);
        assert!(!superblock_spans_device(&sb[..0x40], 4096 * 4096, PAGE));
        assert!(!superblock_spans_device(&[], 0, PAGE));
    }

    fn test_plan() -> Plan {
        Plan::bare_run(Vec::new())
    }

    #[test]
    fn boot_plan_versions_are_checked_before_host_state_or_hooks() {
        let mut boot_plan = BootPlan::new(test_plan());
        boot_plan.plan.on_start.push("exit 99".into());
        boot_plan.plan.host_time = Some(terra_protocol::HostTime {
            seconds: 12,
            nanoseconds: 34,
        });
        boot_plan.plan.host_seed = Some([0; 32]);
        let frame = terra_protocol::encode_frame(&boot_plan).unwrap();
        assert_eq!(
            read_boot_plan(&mut frame.as_slice()).unwrap(),
            boot_plan.plan
        );
        for (agent_version, socket_version) in [
            (
                terra_protocol::AGENT_PROTOCOL_VERSION - 1,
                terra_protocol::socket::VERSION,
            ),
            (
                terra_protocol::AGENT_PROTOCOL_VERSION,
                terra_protocol::socket::VERSION + 1,
            ),
        ] {
            boot_plan.agent_version = agent_version;
            boot_plan.socket_version = socket_version;
            let frame = terra_protocol::encode_frame(&boot_plan).unwrap();
            assert!(read_boot_plan(&mut frame.as_slice()).is_err());
        }
        let bare_plan = terra_protocol::encode_frame(&test_plan()).unwrap();
        assert!(read_boot_plan(&mut bare_plan.as_slice()).is_err());
    }

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
        let mut plan = test_plan();
        plan.env = env;
        setup_env(&plan);
        assert!(std::env::var("PATH").unwrap().starts_with("/custom/bin:"));
        assert_eq!(std::env::var("TERM").unwrap(), "custom-term");
        assert_eq!(
            std::env::var("HOME").unwrap(),
            terra_protocol::WORKLOAD_HOME
        );
    }
}
