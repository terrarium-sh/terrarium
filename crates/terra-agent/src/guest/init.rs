//! Guest init (PID 1): bring the guest up and run the plan.

use crate::vsock::{VMADDR_CID_HOST, VsockStream};
use anyhow::{Context, Result, bail};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use terra_agent::nofollow;
use terra_agent::{
    CONTROL_VSOCK_PORT, Net, Plan, PlanMode, RECIPE_STAMP_PATH, RESIZE2FS_GUEST_PATH, ROOT_DEVICE,
    Share, WORKLOAD_GID, WORKLOAD_UID, WORKLOAD_USER_NAME,
};

/// Bring the guest up, returning once the workload has exited (Run) or
/// `on_create` is baked (Create).
pub fn boot() -> Ending {
    let (plan, control, share_map) = match enter_root() {
        Ok(started) => started,
        Err(e) => {
            return Ending {
                control: None,
                outcome: Err(e),
            };
        }
    };
    let outcome = execute(&plan, &control, share_map.as_ref());
    Ending {
        control: Some(control),
        outcome,
    }
}

/// How a boot ended: the status the host is owed, and the connection it is owed
/// on.
pub struct Ending {
    /// `None` when the boot failed before there was a connection to answer on.
    control: Option<VsockStream>,
    pub outcome: Result<i32>,
}

/// What a boot that never got a status of its own reports.
const AGENT_FAILED: i32 = 1;

impl Ending {
    /// Tell the host how this boot ended, and say whether it was a failure.
    ///
    /// Call it last, after everything else has been printed and with nothing
    /// still owed to the disk: the sync here is what makes the host's teardown
    /// safe to race.
    #[must_use]
    pub fn report(self) -> bool {
        let code = *self.outcome.as_ref().unwrap_or(&AGENT_FAILED);
        // SAFETY: `sync` takes no arguments and cannot fail.
        unsafe { libc::sync() };
        if let Some(mut control) = self.control
            && let Err(e) = terra_agent::send_exit_status(&mut control, code)
        {
            eprintln!("terra-agent: warning: could not report the exit status ({code}): {e}");
        }
        self.outcome.is_err()
    }
}

/// Mount pseudo-filesystems, fetch the plan, grow images, chroot.
///
/// Returns the plan and the control connection it arrived on - the same socket
/// the host later signals a graceful stop over. Raw syscalls throughout: the
/// boot volume holds only the agent and `resize2fs`.
fn enter_root() -> Result<(Plan, VsockStream, Option<std::os::fd::OwnedFd>)> {
    const NEWROOT: &str = "/mnt/root";

    // Mount pseudo-filesystems before the chroot so the recursive bind carries them.
    mount(None, "/proc", Some("proc"), 0).context("mounting /proc")?;
    mount(None, "/sys", Some("sysfs"), 0).context("mounting /sys")?;
    fs::create_dir_all("/dev/pts")?;
    mount(None, "/dev/pts", Some("devpts"), 0).context("mounting /dev/pts")?;
    // Conveniences, not boot requirements: warn and carry on, so a kernel
    // without cgroup2 still gives a usable sandbox.
    fs::create_dir_all("/dev/shm")?;
    for (target, fstype) in [("/dev/shm", "tmpfs"), ("/sys/fs/cgroup", "cgroup2")] {
        if let Err(e) = mount(None, target, Some(fstype), 0) {
            eprintln!("terra: warning: could not mount {target}: {e:#}");
        }
    }
    // Needs /sys and /dev, so it goes here - and before anything worth printing.
    redirect_console_ports();
    // Everything we write lives here: the root is a read-only image.
    mount(None, "/mnt", Some("tmpfs"), 0).context("mounting the staging tmpfs")?;
    fs::create_dir_all(NEWROOT)?;
    fs::create_dir_all("/mnt/clean")?;

    // Plan comes over vsock, never from a file - secrets never touch disk.
    let mut control = VsockStream::connect(VMADDR_CID_HOST, CONTROL_VSOCK_PORT)
        .context("dialling the host control port")?;
    let plan: Plan = terra_agent::read_frame(&mut control).context("reading the boot plan")?;

    // Grow every image before mounting - boot volume is out of reach after chroot.
    grow_filesystem(ROOT_DEVICE, "/mnt/clean");
    for d in &plan.volumes {
        grow_filesystem(&d.dev, "/mnt/clean");
    }

    let share_map = match plan.share_owner {
        Some(owner) if !plan.shares.is_empty() => Some(crate::idmap::owner_userns(owner)?),
        _ => None,
    };

    mount(Some(ROOT_DEVICE), NEWROOT, Some("ext4"), 0)
        .with_context(|| format!("mounting the guest rootfs image ({ROOT_DEVICE})"))?;

    for d in ["proc", "sys", "dev", "terra"] {
        fs::create_dir_all(format!("{NEWROOT}/{d}"))?;
    }
    for d in ["proc", "sys", "dev"] {
        mount(
            Some(&format!("/{d}")),
            &format!("{NEWROOT}/{d}"),
            None,
            libc::MS_BIND | libc::MS_REC,
        )
        .with_context(|| format!("binding /{d} into the guest root"))?;
    }

    let newroot = std::ffi::CString::new(NEWROOT)?;
    unsafe {
        if libc::chroot(newroot.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error()).context("chroot into the guest root");
        }
    }
    // chroot leaves the cwd outside the new root - move it in.
    std::env::set_current_dir("/").context("chdir after chroot")?;
    Ok((plan, control, share_map))
}

/// Bind virtio-console ports so detached output reaches `terra logs`.
fn redirect_console_ports() {
    use std::os::fd::AsRawFd;
    let Ok(ports) = fs::read_dir("/sys/class/virtio-ports") else {
        return;
    };
    for entry in ports.flatten() {
        let Ok(name) = fs::read_to_string(entry.path().join("name")) else {
            continue;
        };
        let (target, writable) = match name.trim() {
            "krun-stdin" => (libc::STDIN_FILENO, false),
            "krun-stdout" => (libc::STDOUT_FILENO, true),
            "krun-stderr" => (libc::STDERR_FILENO, true),
            _ => continue,
        };
        let dev = format!("/dev/{}", entry.file_name().to_string_lossy());
        let opened = if writable {
            fs::OpenOptions::new().write(true).open(&dev)
        } else {
            fs::File::open(&dev)
        };
        match opened {
            Ok(f) if f.as_raw_fd() == target => std::mem::forget(f),
            Ok(f) => unsafe {
                libc::dup2(f.as_raw_fd(), target);
            },
            Err(e) => eprintln!("terra: warning: could not open {dev}: {e}"),
        }
    }
}

/// Grow `dev`'s filesystem via `resize2fs` when it is smaller than the device
/// (`resize2fs` refuses a dirty fs, and every boot after the first is dirty).
///
/// Warn on failure rather than aborting.
fn grow_filesystem(dev: &str, scratch: &str) {
    match undersized(dev) {
        Ok(false) => return,
        Ok(true) => {}
        // Not knowing the size is not a licence to resize anyway: a superblock
        // this could not read is never handed to `resize2fs`.
        Err(e) => {
            eprintln!("terra: warning: could not read {dev}'s superblock ({e}) - skipping resize");
            return;
        }
    }
    // Mount/replay journal to clear dirty flag - avoids shipping e2fsck for it.
    if let Err(e) = mount(Some(dev), scratch, Some("ext4"), 0) {
        eprintln!("terra: warning: {dev} would not mount ({e:#}) - skipping resize");
        return;
    }
    if let Err(e) = umount(scratch) {
        eprintln!("terra: warning: could not unmount {scratch} ({e:#}) - skipping resize");
        return;
    }
    match Command::new(RESIZE2FS_GUEST_PATH)
        .args(["-f", dev])
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("terra: warning: resize2fs {dev} exited {s} - image may be undersized"),
        Err(e) => eprintln!("terra: warning: could not run resize2fs for {dev}: {e}"),
    }
}

/// Whether `dev`'s filesystem is smaller than the device (reads the ext4
/// superblock).
///
/// Both fields come off a disk the *guest* owns - anything that has held guest
/// root can rewrite its superblock - so neither is arithmetic to do plainly. A
/// panic here is a kernel panic in PID 1, and `panic=-1` turns that into a
/// reboot loop: a superblock that does not fit the arithmetic is refused, not
/// resized.
fn undersized(dev: &str) -> Result<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(dev).with_context(|| format!("opening {dev}"))?;
    // Through `s_blocks_count_hi` (offset 0x150): a 64bit-feature image keeps
    // the high word there, and reading only the low one would report a bogus
    // size - and resize on every boot - past 2^32 blocks.
    let mut sb = [0u8; 0x154];
    f.seek(SeekFrom::Start(1024))?;
    f.read_exact(&mut sb)?;
    let blocks = u64::from(u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]))
        | u64::from(u32::from_le_bytes([
            sb[0x150], sb[0x151], sb[0x152], sb[0x153],
        ])) << 32;
    let shift = u32::from_le_bytes([sb[24], sb[25], sb[26], sb[27]]);
    let device_size = f.seek(SeekFrom::End(0))?;
    // ext4 caps `s_log_block_size` at 6 (64 KiB blocks). `checked_shl` is not the
    // guard it looks like - it only refuses a shift past the word width, and
    // `1024 << 60` wraps to zero inside it.
    let Some(size) = (shift <= 6)
        .then(|| 1024u64 << shift)
        .and_then(|block_size| blocks.checked_mul(block_size))
    else {
        bail!("{dev} has an ext4 superblock claiming {blocks} blocks of 1024<<{shift} bytes");
    };
    Ok(size < device_size)
}

fn umount(target: &str) -> Result<()> {
    let target_c = std::ffi::CString::new(target)?;
    if unsafe { libc::umount(target_c.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("umount {target}"));
    }
    Ok(())
}

fn mount(source: Option<&str>, target: &str, fstype: Option<&str>, flags: u64) -> Result<()> {
    let c = |s: &str| std::ffi::CString::new(s);
    let source = c(source.unwrap_or("none"))?;
    let target_c = c(target)?;
    let fstype = fstype.map(c).transpose()?;
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target_c.as_ptr(),
            fstype.as_ref().map_or(std::ptr::null(), |f| f.as_ptr()),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("mount {target}"));
    }
    Ok(())
}

/// Run the plan, handing back the status the box ended with: the workload's, or
/// a bake's (which is a success or nothing - a failed hook is the `Err`).
fn execute(
    plan: &Plan,
    control: &VsockStream,
    share_map: Option<&std::os::fd::OwnedFd>,
) -> Result<i32> {
    // The agent's vsock port, before anything else in this guest runs. Not a
    // detail of starting the workload: `setup_net` below already execs `ip`, the
    // hooks are arbitrary recipe shell running as root, and every binary any of
    // them reaches lives in the box's own persistent, guest-writable rootfs. The
    // guest kernel has vsock loopback, so the port belongs to whoever binds it
    // first - and a process that won the race would answer `terra put`/`get` and
    // `terra exec` in the agent's place, in the one situation exec exists for:
    // looking into a box you no longer trust. A port that will not bind is
    // fatal for the same reason, and only defensible at this point: nothing
    // else in the guest has run yet.
    let port = crate::vsock::VsockListener::bind(terra_agent::AGENT_VSOCK_PORT)
        .map_err(|e| anyhow::anyhow!("binding the agent port: {e}"))?;

    restrict_ptrace();

    // Environment and NIC first: both modes' hooks may use either.
    setup_env(plan);
    setup_net(&plan.net)?;

    // HOME is the workload's in every mode, so it must exist even in a bake,
    // which has not created its user yet.
    let home = terra_agent::workload_home();
    if ensure_workdir(&home).with_context(|| format!("creating workdir {home}"))? {
        give_to_workload(&home);
    }

    // A Create VM has no shares and is guest root.
    if plan.mode == PlanMode::Create {
        return bake_if_stale(&plan.on_create).map(|()| 0);
    }
    ensure_baked(&plan.on_create)?;

    for s in &plan.shares {
        mount_share(s, share_map)?;
    }
    // Volumes are guest-local ext4; hand each one's root to the workload user
    // so both guest users can write.
    for d in &plan.volumes {
        prepare_mount_point(&d.guest)?;
        mount(Some(&d.dev), &d.guest, Some("ext4"), 0)?;
        if !plan.root {
            // After the mount, so this is the volume's own root inode rather
            // than the directory it was mounted over.
            give_to_workload(&d.guest);
        }
    }
    fs::write("/terra/README.md", &plan.sandbox_info).context("writing sandbox description")?;
    setup_user(plan.root);
    setup_sudo(plan.root, &plan.sudo)?;
    for line in &plan.on_start {
        sh(line)?;
    }

    let workdir = plan
        .workdir
        .clone()
        .unwrap_or_else(terra_agent::workload_home);
    let created =
        ensure_workdir(&workdir).with_context(|| format!("creating workdir {workdir}"))?;
    if created {
        give_to_workload(&workdir);
    }
    std::env::set_current_dir(&workdir).with_context(|| format!("entering workdir {workdir}"))?;

    crate::reap::watch_orphans();

    // A clone, because the status this ends with still has to go back out on it.
    let (code, session) = crate::term::mux::run_workload(
        &plan.workload,
        control
            .try_clone()
            .context("cloning the control connection")?,
        plan.root,
        port,
        plan.workload_on_console,
    )
    .context("running the workload")?;

    // Best-effort: failing cleanup should not mask the exit.
    for line in &plan.pre_stop {
        sh_ok_within(line, PRE_STOP_TIMEOUT);
    }
    session.broadcast_exit(code, CLIENT_EXIT_GRACE);
    Ok(code)
}

/// How long the guest waits for an attached client to take the workload's exit
/// status before it stops anyway.
const CLIENT_EXIT_GRACE: Duration = Duration::from_secs(2);

/// What the baked stamp says about this boot's `on_create` - the one reading
/// of [`RECIPE_STAMP_PATH`], shared by both modes so they cannot disagree.
enum StampState {
    /// The stamp holds this very recipe: the bake already ran.
    UpToDate,
    /// A *different* `on_create` is already baked in; re-applying over a
    /// filesystem that persists is the double-apply hazard, so it is kept,
    /// with a warning (`terra rm` rebuilds).
    ChangedKept,
    /// Nothing was ever applied: no stamp, or an empty one.
    NeverBaked,
}

/// An unreadable stamp - truncated, an I/O error - is an error, never
/// [`StampState::NeverBaked`]: that would re-run `on_create` over a filesystem
/// that persists.
fn stamp_state(recipe: &str) -> Result<StampState> {
    match fs::read_to_string(RECIPE_STAMP_PATH) {
        Ok(stamped) if stamped == recipe => Ok(StampState::UpToDate),
        Ok(stamped) if !stamped.is_empty() => {
            eprintln!(
                "terra: warning: on_create changed since this box was created, and \
                 the old one is already baked in; keeping it (`terra rm` rebuilds)"
            );
            Ok(StampState::ChangedKept)
        }
        Ok(_) => Ok(StampState::NeverBaked),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StampState::NeverBaked),
        Err(e) => Err(e).context(format!("reading {RECIPE_STAMP_PATH}")),
    }
}

/// Run `on_create` if the stamp says it never ran - Create VMs only. Stamp only
/// written on success, so a failed bake is retried on the next `terra setup`.
fn bake_if_stale(on_create: &[String]) -> Result<()> {
    let recipe = on_create.join("\n");
    match stamp_state(&recipe)? {
        StampState::UpToDate | StampState::ChangedKept => return Ok(()),
        StampState::NeverBaked => {}
    }
    if !on_create.is_empty() {
        println!("terra: baking on_create…");
    }
    for line in on_create {
        sh(line)?;
    }
    fs::write(RECIPE_STAMP_PATH, &recipe).with_context(|| format!("stamping {RECIPE_STAMP_PATH}"))
}

/// A Run boot never bakes (the host runs every bake in an isolated Create VM),
/// but it must not run a workload over a filesystem whose bake never finished,
/// silently missing whatever `on_create` was for.
fn ensure_baked(on_create: &[String]) -> Result<()> {
    if on_create.is_empty() {
        return Ok(());
    }
    match stamp_state(&on_create.join("\n"))? {
        StampState::UpToDate | StampState::ChangedKept => Ok(()),
        StampState::NeverBaked => bail!(
            "this box's on_create never finished baking - `terra setup` re-runs it \
             (`--rebuild` for a clean slate)"
        ),
    }
}

/// Prepare a mount point in the box's *persistent* rootfs, refusing a path
/// that traverses a symlink.
fn prepare_mount_point(path: &str) -> Result<()> {
    let as_dir =
        || nofollow::open_no_symlinks_raw(Path::new(path), libc::O_PATH | libc::O_DIRECTORY, 0);
    let refuse = |e: &std::io::Error| {
        let why = if e.raw_os_error() == Some(libc::ELOOP) {
            "it, or a directory above it, is a symlink"
        } else {
            "it cannot be opened as a directory"
        };
        anyhow::anyhow!(
            "refusing to mount at {path}: {why} ({e}) - either the guest filesystem \
             ships one there (mount somewhere else) or something inside this box put \
             it there (`terra rm` rebuilds the filesystem)"
        )
    };
    match as_dir() {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // nothing there yet
        Err(e) => bail!(refuse(&e)),
    }
    fs::create_dir_all(path).with_context(|| format!("creating mount point {path}"))?;
    as_dir().map(drop).map_err(|e| refuse(&e))
}

/// Confine `ptrace` to a process's own descendants (Yama scope 1): the LSM
/// does nothing until this is written - its default is 0 - and without it one
/// workload process could read another's memory just for sharing a uid. Scope
/// 1 is Ubuntu's default, so tracing one's own descendants still works; a
/// kernel without Yama gets a warning rather than a boot failure.
fn restrict_ptrace() {
    const PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";
    if let Err(e) = fs::write(PATH, "1\n") {
        eprintln!("terra: warning: could not restrict ptrace ({PATH}): {e}");
    }
}

/// Mount a virtiofs share, idmapped through the owner map when there is one
/// (see [`crate::idmap`]). Only PID 1 can set the map, which is what keeps the
/// mapping the host's decision.
fn mount_share(s: &Share, owner_map: Option<&std::os::fd::OwnedFd>) -> Result<()> {
    prepare_mount_point(&s.guest)?;
    let flags = if s.readonly { libc::MS_RDONLY } else { 0 };
    mount(Some(&s.tag), &s.guest, Some("virtiofs"), flags)?;
    if let Some(userns) = owner_map {
        crate::idmap::remount_idmapped(&s.guest, userns)
            .with_context(|| format!("idmapping the share at {}", s.guest))?;
    }
    Ok(())
}

/// PID 1 gets an empty environment; every hook, command, and the workload
/// inherits what we set.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Establish the guest's base environment, then apply `plan.env` on top.
fn setup_env(plan: &Plan) {
    let home = terra_agent::workload_home();
    unsafe {
        std::env::set_var("PATH", DEFAULT_PATH);
        std::env::set_var("HOME", home);
        std::env::set_var("TERM", "xterm-256color");
        for (k, v) in &plan.env {
            std::env::set_var(k, v);
        }
    }
    let name = b"terrarium";
    unsafe { libc::sethostname(name.as_ptr().cast::<libc::c_char>(), name.len()) };
}

/// Static NIC config (no DHCP in the VM).
fn setup_net(net: &Net) -> Result<()> {
    run("ip", &["link", "set", "lo", "up"])?;
    run(
        "ip",
        &[
            "addr",
            "add",
            &format!("{}/{}", net.guest_ip, net.prefix),
            "dev",
            "eth0",
        ],
    )?;
    run("ip", &["link", "set", "eth0", "up"])?;
    run("ip", &["route", "add", "default", "via", &net.gateway])?;
    fs::write("/etc/resolv.conf", format!("nameserver {}\n", net.dns))
        .context("writing /etc/resolv.conf")
}

/// Guest path of the `doas` policy. `doas` (and the `sudo` shim next to it) are
/// baked into the image; both grant nothing until this file says otherwise.
const DOAS_CONF: &str = "/etc/doas.conf";

/// The drop-in directory `doas` reads alongside [`DOAS_CONF`]. It lives in the
/// box's *persistent* filesystem, so a rule left here by anything that once held
/// root would outlive the `sudo:` line that allowed it - which is the whole
/// promise of rewriting the policy every boot.
const DOAS_DIR: &str = "/etc/doas.d";

/// Grant `sudo` commands to the workload user. Rewritten on every boot so
/// removed grants aren't left behind. Convenience, not a sandbox boundary.
fn setup_sudo(root: bool, commands: &[String]) -> Result<()> {
    use std::fmt::Write as _;
    if root {
        return Ok(());
    }
    // The drop-ins first: a stale one there would outrank whatever is written
    // below (see [`DOAS_DIR`]). Removal *is* the security property, so a
    // drop-in that cannot be removed fails the boot rather than surviving it.
    match fs::read_dir(DOAS_DIR) {
        Ok(entries) => {
            for entry in entries {
                let path = entry.with_context(|| format!("reading {DOAS_DIR}"))?.path();
                if path.extension().is_some_and(|x| x == "conf") {
                    fs::remove_file(&path).with_context(|| {
                        format!("removing the stale doas drop-in {}", path.display())
                    })?;
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context(format!("reading {DOAS_DIR}")),
    }
    let mut policy =
        String::from("# Generated by terra from the profile's `sudo:` - edits are overwritten.\n");
    for cmd in commands {
        // doas matches by uid, so this holds even if the passwd entry is edited.
        let _ = writeln!(policy, "permit nopass {WORKLOAD_UID} cmd {cmd}");
    }
    fs::write(DOAS_CONF, policy).with_context(|| format!("writing {DOAS_CONF}"))?;
    // doas refuses a policy that others can write.
    fs::set_permissions(DOAS_CONF, std::fs::Permissions::from_mode(0o640))
        .with_context(|| format!("securing {DOAS_CONF}"))?;
    Ok(())
}

/// Create the workload user, once; a failure is warned about, not silent - a
/// silent one used to leave the workload running as a uid with no passwd entry
/// and no home.
fn setup_user(root: bool) {
    if root {
        return;
    }
    let entry = format!("{WORKLOAD_USER_NAME}:");
    if fs::read_to_string("/etc/passwd").is_ok_and(|p| p.lines().any(|l| l.starts_with(&entry))) {
        return;
    }
    let (uid, gid) = (WORKLOAD_UID.to_string(), WORKLOAD_GID.to_string());
    let quiet = |cmd: &str, args: &[&str]| {
        let status = Command::new(cmd)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => eprintln!(
                "terra: warning: `{cmd}` exited {s} - the {WORKLOAD_USER_NAME} user may be missing"
            ),
            Err(e) => eprintln!("terra: warning: could not run `{cmd}`: {e}"),
        }
    };
    quiet("addgroup", &["-g", &gid, WORKLOAD_USER_NAME]);
    quiet(
        "adduser",
        &[
            "-D",
            "-u",
            &uid,
            "-G",
            WORKLOAD_USER_NAME,
            WORKLOAD_USER_NAME,
        ],
    );
}

/// Hand a directory to the workload user, best-effort - a chown that will not
/// take (a mount without the host userns, say) should not fail the boot.
fn give_to_workload(path: &str) {
    let Ok(path_c) = std::ffi::CString::new(path) else {
        return;
    };
    // SAFETY: a NUL-terminated path; failure is reported by rc, and ignored.
    let _ = unsafe { libc::chown(path_c.as_ptr(), WORKLOAD_UID, WORKLOAD_GID) };
}

/// Make `dir` exist, reporting whether it had to be created.
fn ensure_workdir(dir: &str) -> std::io::Result<bool> {
    if Path::new(dir).exists() {
        return Ok(false);
    }
    fs::create_dir_all(dir)?;
    Ok(true)
}

// ---- command helpers -------------------------------------------------------

/// Run a command, error on non-zero.
fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = crate::reap::status_owned(Command::new(cmd).args(args))
        .with_context(|| format!("spawning `{cmd}`"))?;
    if !status.success() {
        bail!("`{cmd} {}` failed ({status})", args.join(" "));
    }
    Ok(())
}

/// Run a hook line through the shell (`on_create`/`on_start`).
fn sh(line: &str) -> Result<()> {
    let status = crate::reap::status_owned(Command::new("sh").arg("-c").arg(line))
        .with_context(|| format!("spawning hook `{line}`"))?;
    if !status.success() {
        bail!("hook `{line}` failed ({status})");
    }
    Ok(())
}

/// How long a single `pre_stop` line may take before it is killed. Flushing
/// and unmounting is a seconds job; longer is a hook not coming back.
const PRE_STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Run a `pre_stop` hook line through the shell, ignoring failure. The timeout
/// is a parameter only so a test need not wait out [`PRE_STOP_TIMEOUT`].
fn sh_ok_within(line: &str, timeout: Duration) {
    let Ok(mut child) = crate::reap::spawn_owned(|| Command::new("sh").arg("-c").arg(line).spawn())
    else {
        return;
    };
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) => {}
        }
        if std::time::Instant::now() >= deadline {
            eprintln!(
                "terra-agent: pre_stop hook `{line}` still running after {}s - killing it",
                timeout.as_secs()
            );
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // `wait` after a successful `try_wait` returns the cached status, so this
    // is safe on the already-exited path too.
    let _ = crate::reap::wait_owned(&mut child);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("terra-agent-init-{}-{name}", std::process::id()))
    }

    /// A mount point's parents can belong to the workload from a previous boot -
    /// the rootfs persists - and `create_dir_all` follows a symlink to a
    /// directory and reports success. Mounting through one puts a read-write host
    /// share, or a volume this then chowns to the workload user, wherever the
    /// workload pointed it: `/usr/local/bin`, say, which `$PATH` reaches first.
    ///
    /// Both spellings have to be refused. The leaf was; a symlinked *parent* was
    /// not, because an `lstat` of the whole path resolves everything above the
    /// last component on its way - so the link answered for the directory behind
    /// it and the mount landed on the far side.
    #[test]
    fn a_symlinked_mount_point_is_refused() {
        let real = scratch("mp-real");
        let link = scratch("mp-link");
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_file(&link);
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // (a) the mount point itself.
        let err = prepare_mount_point(&link.to_string_lossy())
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");

        // (b) a directory above it - `guest: /home/terri/work/src` with `work`
        //     replaced. Nothing may be created on the other side either.
        let under = link.join("src");
        let err = prepare_mount_point(&under.to_string_lossy())
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        assert!(
            !real.join("src").exists(),
            "the mount point was created through the link"
        );

        // An ordinary path - existing or not, nested or not - is prepared as before.
        assert!(prepare_mount_point(&real.to_string_lossy()).is_ok());
        let fresh = scratch("mp-fresh");
        let _ = fs::remove_dir_all(&fresh);
        assert!(prepare_mount_point(&fresh.join("a/b").to_string_lossy()).is_ok());
        assert!(fresh.join("a/b").is_dir());

        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_dir_all(&fresh);
    }

    /// `pre_stop` runs on the way to `exit`, and PID 1 returning is what ends the
    /// VM - so an unbounded hook is a VM that never stops. The binary a hook
    /// invokes lives in the box's own guest-writable rootfs, so a box can arrange
    /// this for itself.
    #[test]
    fn a_wedged_pre_stop_hook_is_killed() {
        let start = std::time::Instant::now();
        sh_ok_within("sleep 600", Duration::from_millis(300));
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "sh_ok waited {:?} on a hook that never returns",
            start.elapsed()
        );
        // …and a hook that does return is not waited out.
        let start = std::time::Instant::now();
        sh_ok_within("true", PRE_STOP_TIMEOUT);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// A recipe naming a workdir gets one, nested parents and all - starting
    /// somewhere else would resolve every relative path the workload uses
    /// against the wrong tree. But only a directory terra created is handed to
    /// the workload user.
    #[test]
    fn a_missing_workdir_is_created_and_an_existing_one_is_left_alone() {
        let base = scratch("workdir");
        let _ = fs::remove_dir_all(&base);
        let path = |p: &std::path::Path| p.to_string_lossy().into_owned();
        let nested = base.join("a/b/work");

        // Created, parents and all, and claimed by the caller.
        assert!(ensure_workdir(&path(&nested)).unwrap());
        assert!(nested.is_dir());

        // Already there: not claimed, so a share's mount point keeps its owner.
        assert!(!ensure_workdir(&path(&nested)).unwrap());

        // A file on the path is left alone as well.
        let file = base.join("afile");
        fs::write(&file, b"x").unwrap();
        assert!(!ensure_workdir(&path(&file)).unwrap());
        assert!(file.is_file());

        let _ = fs::remove_dir_all(&base);
    }
}
