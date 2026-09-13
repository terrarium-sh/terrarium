//! Guest init (PID 1): bring the guest up and run the plan.

use crate::term::session::{
    DEFAULT_COLS, DEFAULT_ROWS, MAX_COLS, MAX_ROWS, MIN_COLS, MIN_ROWS, Session, Sink,
};
use crate::vsock::{VMADDR_CID_HOST, VsockListener, connect};
use anyhow::{Context, Result, bail};
use pty_process::blocking::Command as PtyCommand;
use pty_process::blocking::{Pts, Pty};
use rustix::mount::{MountFlags, MountPropagationFlags};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use terra_protocol::{
    CLOCK_SYNC, CLOCK_SYNC_BYTES, CONTROL_VSOCK_PORT, DEFAULT_STOP_GRACE_SECS,
    DIAGNOSTIC_VSOCK_PORT, LifecycleEvent, LifecycleProtocol, Net, Plan, PlanMode,
    RECIPE_STAMP_PATH, RESIZE2FS_GUEST_PATH, ROOT_DEVICE, STOP_SIGNAL, Share, WORKLOAD_ID,
    WORKLOAD_USER_NAME,
};

const AGENT_FAILED: i32 = 1;
const CLEAN_MOUNT: &str = "/mnt/clean";
const DIAGNOSTIC_CHUNK_BYTES: usize = 4096;
const DIAGNOSTIC_QUEUE_BYTES: usize = 64 << 10;
const DIAGNOSTIC_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const SUBORDINATE_ID_START: u32 = 100_000;
const SUBORDINATE_ID_COUNT: u32 = 65_536;

#[derive(Clone)]
struct Diagnostics {
    sender: mpsc::SyncSender<Vec<u8>>,
    finished: Arc<Mutex<mpsc::Receiver<std::io::Result<()>>>>,
}

impl Diagnostics {
    fn new(mut writer: File) -> Self {
        let (sender, receiver) =
            mpsc::sync_channel::<Vec<u8>>(DIAGNOSTIC_QUEUE_BYTES / DIAGNOSTIC_CHUNK_BYTES);
        let (done, finished) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = receiver
                .into_iter()
                .try_for_each(|bytes| write_diagnostic(&mut writer, &bytes));
            let _ = done.send(result);
        });
        Self {
            sender,
            finished: Arc::new(Mutex::new(finished)),
        }
    }

    fn record(&self, bytes: &[u8]) {
        for bytes in bytes.chunks(DIAGNOSTIC_CHUNK_BYTES) {
            if self.sender.try_send(bytes.to_vec()).is_err() {
                break;
            }
        }
    }

    fn finish(self) {
        let Self { sender, finished } = self;
        drop(sender);
        let _ = finished
            .lock()
            .ok()
            .and_then(|receiver| receiver.recv_timeout(Duration::from_secs(1)).ok());
    }
}

pub fn boot() -> ! {
    let (control, outcome) = match enter_root() {
        Ok((plan, control, diagnostic)) => {
            let outcome = execute(&plan, &control, diagnostic.as_ref());
            (
                Some((control, diagnostic, plan.lifecycle_protocol)),
                outcome,
            )
        }
        Err(e) => (None, Err(e)),
    };
    if let Err(e) = &outcome {
        eprintln!("terra-agent: init failed: {e:#}");
        if let Ok(mut kernel_log) = fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            let _ = kernel_log.write_all(format!("terra-agent: init failed: {e:#}\n").as_bytes());
        }
    }

    let code = *outcome.as_ref().unwrap_or(&AGENT_FAILED);
    // Disk sync happens before reporting so host teardown is safe to race.
    rustix::fs::sync();
    if let Some((mut control, diagnostic, lifecycle_protocol)) = control {
        if let Some(diagnostic) = diagnostic {
            if let Err(error) = &outcome {
                diagnostic.record(format!("terra-agent: init failed: {error:#}").as_bytes());
            }
            diagnostic.finish();
        }
        let report = write_exit_report(&mut control, lifecycle_protocol, code);
        if let Err(e) = report {
            eprintln!("terra-agent: warning: could not report the exit status ({code}): {e}");
        } else if lifecycle_protocol == LifecycleProtocol::EventsV1 {
            // Powering off would reset virtio before the host drains the exit frame.
            loop {
                std::thread::park();
            }
        }
    }
    if let Err(e) = rustix::system::reboot(rustix::system::RebootCommand::PowerOff) {
        eprintln!("terra-agent: could not power off after reporting exit status: {e}");
    }
    std::process::exit(i32::from(outcome.is_err()))
}

fn write_exit_report(
    writer: &mut impl Write,
    lifecycle_protocol: LifecycleProtocol,
    code: i32,
) -> std::io::Result<()> {
    let frame = match lifecycle_protocol {
        LifecycleProtocol::Legacy => terra_protocol::encode_frame(&code)?,
        LifecycleProtocol::EventsV1 => {
            terra_protocol::encode_frame(&LifecycleEvent::Exit { code })?
        }
    };
    writer.write_all(&frame).and_then(|()| writer.flush())
}

fn write_diagnostic(writer: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    let bytes = bytes[..bytes
        .len()
        .min(terra_protocol::control::MAX_DIAGNOSTIC_EVENT_BYTES)]
        .to_vec();
    let frame = terra_protocol::encode_frame(&LifecycleEvent::Diagnostic { bytes })?;
    writer.write_all(&frame).and_then(|()| writer.flush())
}

fn enter_root() -> Result<(Plan, File, Option<Diagnostics>)> {
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
            eprintln!("terra: warning: could not mount {target}: {e:#}");
        }
    }
    mount(None, "/mnt", Some("tmpfs"), MountFlags::empty())
        .context("mounting the staging tmpfs")?;
    fs::create_dir_all(NEWROOT)?;
    fs::create_dir_all(CLEAN_MOUNT)?;

    let mut control =
        connect(VMADDR_CID_HOST, CONTROL_VSOCK_PORT).context("dialling the host control port")?;
    let plan: Plan =
        terra_protocol::read_frame_with_limit(&mut control, terra_protocol::MAX_PLAN_BYTES)
            .context("reading the boot plan")?
            .ok_or_else(|| anyhow::anyhow!("control channel closed before receiving boot plan"))?;
    setup_env(&plan);
    apply_host_state(&plan)?;
    let diagnostic = if plan.lifecycle_protocol == LifecycleProtocol::EventsV1 {
        let mut diagnostic = connect(VMADDR_CID_HOST, DIAGNOSTIC_VSOCK_PORT)
            .context("dialling the host diagnostic port")?;
        rustix::net::sockopt::set_socket_timeout(
            &diagnostic,
            rustix::net::sockopt::Timeout::Send,
            Some(DIAGNOSTIC_WRITE_TIMEOUT),
        )
        .context("setting the host diagnostic write deadline")?;
        write_diagnostic(&mut diagnostic, b"agent received boot plan")?;
        Some(Diagnostics::new(diagnostic))
    } else {
        redirect_console_ports();
        None
    };

    grow_filesystem(ROOT_DEVICE);
    for d in &plan.volumes {
        grow_filesystem(&d.dev);
    }

    mount(
        Some(ROOT_DEVICE),
        NEWROOT,
        Some("ext4"),
        MountFlags::empty(),
    )
    .with_context(|| format!("mounting the guest rootfs image ({ROOT_DEVICE})"))?;

    for d in ["proc", "sys", "dev", "terra"] {
        fs::create_dir_all(format!("{NEWROOT}/{d}"))?;
    }
    for d in ["proc", "sys", "dev"] {
        mount(
            Some(&format!("/{d}")),
            &format!("{NEWROOT}/{d}"),
            None,
            rustix::mount::MountFlags::BIND | rustix::mount::MountFlags::REC,
        )
        .with_context(|| format!("binding /{d} into the guest root"))?;
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
    Ok((plan, control, diagnostic))
}

fn redirect_console_ports() {
    let Ok(ports) = fs::read_dir("/sys/class/virtio-ports") else {
        return;
    };
    for entry in ports.flatten() {
        let Ok(name) = fs::read_to_string(entry.path().join("name")) else {
            continue;
        };
        let (target, writable, duplicate) = match name.trim() {
            "krun-stdin" => (
                0,
                false,
                (|file: &File| rustix::stdio::dup2_stdin(file))
                    as fn(&File) -> rustix::io::Result<()>,
            ),
            "krun-stdout" => (
                1,
                true,
                (|file: &File| rustix::stdio::dup2_stdout(file))
                    as fn(&File) -> rustix::io::Result<()>,
            ),
            "krun-stderr" => (
                2,
                true,
                (|file: &File| rustix::stdio::dup2_stderr(file))
                    as fn(&File) -> rustix::io::Result<()>,
            ),
            _ => continue,
        };
        let dev = format!("/dev/{}", entry.file_name().to_string_lossy());
        let opened = if writable {
            fs::OpenOptions::new().write(true).open(&dev)
        } else {
            fs::File::open(&dev)
        };
        match opened {
            // Keep fd open so stdio does not close with it.
            Ok(f) if f.as_raw_fd() == target => {
                let _ = rustix::io::fcntl_setfd(&f, rustix::io::FdFlags::empty());
                std::mem::forget(f);
            }
            Ok(f) => {
                let _ = duplicate(&f);
            }
            Err(e) => eprintln!("terra: warning: could not open {dev}: {e}"),
        }
    }
}

fn grow_filesystem(dev: &str) {
    if let Err(e) = mount(Some(dev), CLEAN_MOUNT, Some("ext4"), MountFlags::empty()) {
        eprintln!("terra: warning: {dev} would not mount ({e:#}) - skipping resize");
        return;
    }
    if let Err(e) = rustix::mount::unmount(CLEAN_MOUNT, rustix::mount::UnmountFlags::empty())
        .map_err(std::io::Error::from)
        .with_context(|| format!("umount {CLEAN_MOUNT}"))
    {
        eprintln!("terra: warning: could not unmount {CLEAN_MOUNT} ({e:#}) - skipping resize");
        let _ = rustix::mount::unmount(CLEAN_MOUNT, rustix::mount::UnmountFlags::DETACH);
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

fn apply_tz(bytes: Option<&[u8]>) {
    if let Some(bytes) = bytes.filter(|bytes| !bytes.is_empty()) {
        let _ = std::fs::create_dir_all("/etc");
        let tmp = "/etc/.localtime.tmp";
        if let Err(e) = std::fs::write(tmp, bytes) {
            eprintln!("terra-agent: warning: could not write /etc/localtime: {e}");
        } else {
            let _ = std::fs::rename(tmp, "/etc/localtime");
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
    // SAFETY: RNDADDENTROPY reads this exact C layout and all 32 bytes are a
    // fresh trusted WASI secure-random seed, so crediting 256 bits is sound.
    let request =
        unsafe { rustix::ioctl::Setter::<{ linux_raw_sys::ioctl::RNDADDENTROPY }, _>::new(credit) };
    // SAFETY: `/dev/random` implements RNDADDENTROPY and `request` owns the
    // matching input buffer for the call.
    unsafe { rustix::ioctl::ioctl(&random, request) }
        .map_err(std::io::Error::from)
        .context("crediting the guest CSPRNG")?;
    Ok(())
}

fn synchronize_clock(seconds: i64, nanoseconds: u32, bootstrap: bool) -> Result<()> {
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

fn read_clock_update(reader: &mut impl Read) -> Result<()> {
    let mut bytes = [0; CLOCK_SYNC_BYTES];
    bytes[0] = CLOCK_SYNC;
    reader
        .read_exact(&mut bytes[1..])
        .context("reading clock update")?;
    let (seconds, nanoseconds) = terra_protocol::decode_clock_sync(&bytes)
        .ok_or_else(|| anyhow::anyhow!("invalid clock update"))?;
    synchronize_clock(seconds, nanoseconds, false)
}

struct ClockFrame {
    bytes: [u8; CLOCK_SYNC_BYTES],
    len: usize,
}

impl ClockFrame {
    fn new() -> Self {
        let mut bytes = [0; CLOCK_SYNC_BYTES];
        bytes[0] = CLOCK_SYNC;
        Self { bytes, len: 1 }
    }

    fn decode(&self) -> Result<(i64, u32)> {
        (self.len == CLOCK_SYNC_BYTES)
            .then(|| terra_protocol::decode_clock_sync(&self.bytes))
            .flatten()
            .ok_or_else(|| anyhow::anyhow!("invalid clock update"))
    }
}

fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: rustix::mount::MountFlags,
) -> Result<()> {
    rustix::mount::mount(
        source.unwrap_or("none"),
        target,
        fstype.unwrap_or("none"),
        flags,
        c"",
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("mounting {target}"))
}

#[allow(unsafe_code)]
fn execute(plan: &Plan, control: &File, diagnostic: Option<&Diagnostics>) -> Result<i32> {
    // The vsock port is bound before any hooks or network run.
    // Otherwise guest code could bind it first over vsock loopback and hijack agent services.
    let port = crate::vsock::VsockListener::bind(terra_protocol::AGENT_VSOCK_PORT)
        .map_err(|e| anyhow::anyhow!("binding the agent port: {e}"))?;

    restrict_ptrace();
    crate::reap::watch_orphans();
    setup_net(&plan.net)?;

    // HOME is the workload's in every mode, so it must exist even in a bake,
    // which has not created its user yet.
    let home = terra_protocol::WORKLOAD_HOME;
    crate::files::ensure_directory(Path::new(home), true)
        .with_context(|| format!("creating home {home}"))?;

    // A Create VM has no shares and is guest root.
    if plan.mode == PlanMode::Create {
        return bake_if_stale(&plan.on_create, diagnostic).map(|()| 0);
    }
    ensure_baked(&plan.on_create)?;

    for s in &plan.shares {
        mount_share(s)?;
    }
    // Volumes are guest-local ext4; hand each one's root to the workload user
    // so both guest users can write.
    for d in &plan.volumes {
        prepare_mount_point(&d.guest)?;
        mount(
            Some(&d.dev),
            &d.guest,
            Some("ext4"),
            MountFlags::NOSUID | MountFlags::NODEV,
        )?;
        if !plan.root {
            // Chown after mount targets the volume's root inode, not the underlying directory.
            if let Err(e) = rustix::fs::chown(
                &d.guest,
                Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
                Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
            ) {
                eprintln!("terra: warning: could not chown {}: {e}", d.guest);
            }
        }
    }
    fs::write("/terra/README.md", &plan.sandbox_info).context("writing sandbox description")?;
    setup_user(plan.root)?;
    setup_sudo(plan.root, &plan.sudo)?;
    let startup = crate::vsock::StartupGate::new();
    let SessionPty {
        session,
        pts,
        drained,
    } = start_session(plan, control, port, startup.clone())?;
    if !plan.on_start.is_empty() {
        session.feed_output(b"terra: running startup hooks\r\n");
    }
    for line in &plan.on_start {
        if let Err(error) = run_hook(line, Some(HOOK_TIMEOUT), diagnostic, Some(&session)) {
            startup.fail();
            session.feed_output(format!("terra-agent: init failed: {error:#}\r\n").as_bytes());
            session.broadcast_exit(AGENT_FAILED);
            return Err(error);
        }
    }

    let workdir = plan
        .workdir
        .clone()
        .unwrap_or_else(|| terra_protocol::WORKLOAD_HOME.to_owned());
    if let Err(error) = crate::files::ensure_directory(Path::new(&workdir), !plan.root)
        .with_context(|| format!("creating workdir {workdir}"))
        .and_then(|()| {
            std::env::set_current_dir(&workdir)
                .with_context(|| format!("entering workdir {workdir}"))
        })
    {
        startup.fail();
        session.feed_output(format!("terra-agent: init failed: {error:#}\r\n").as_bytes());
        session.broadcast_exit(AGENT_FAILED);
        return Err(error);
    }

    startup.ready();

    let stop_grace = Duration::from_secs(DEFAULT_STOP_GRACE_SECS);

    let outcome = run_workload(plan, control, pts, &drained, session.clone(), stop_grace);
    let (code, session, daemons) = match outcome {
        Ok(pair) => pair,
        Err(e) => return Err(e.context("running the workload")),
    };

    // Daemons stay up through pre_stop hooks in case hooks interact with them.
    if !plan.pre_stop.is_empty() {
        session.feed_output(b"terra: running stop hooks\r\n");
    }
    for line in &plan.pre_stop {
        if let Err(error) = run_hook(line, Some(HOOK_TIMEOUT), diagnostic, Some(&session)) {
            session.feed_output(format!("terra-agent: stop hook failed: {error:#}\r\n").as_bytes());
        }
    }
    daemons.stop(stop_grace);
    session.broadcast_exit(code);
    Ok(code)
}

fn is_baked(recipe: &str) -> Result<bool> {
    match fs::read_to_string(RECIPE_STAMP_PATH) {
        Ok(stamped) if stamped == recipe => Ok(true),
        Ok(stamped) if !stamped.is_empty() => {
            eprintln!(
                "terra: warning: on_create changed since this box was created, and \
                 the old one is already baked in; keeping it (`terra rm` rebuilds)"
            );
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).context(format!("reading {RECIPE_STAMP_PATH}")),
    }
}

fn ensure_baked(on_create: &[String]) -> Result<()> {
    if on_create.is_empty() || is_baked(&on_create.join("\n"))? {
        return Ok(());
    }
    bail!(
        "this box's on_create never finished baking - `terra setup` re-runs it \
         (`--rebuild` for a clean slate)"
    );
}

fn bake_if_stale(on_create: &[String], diagnostic: Option<&Diagnostics>) -> Result<()> {
    let recipe = on_create.join("\n");
    if is_baked(&recipe)? {
        return Ok(());
    }
    if !on_create.is_empty() {
        if let Some(diagnostic) = diagnostic {
            diagnostic.record(b"terra: baking on_create...\n");
        } else {
            println!("terra: baking on_create…");
        }
    }
    for line in on_create {
        run_hook(line, Some(HOOK_TIMEOUT), diagnostic, None)?;
    }
    fs::write(RECIPE_STAMP_PATH, &recipe).with_context(|| format!("stamping {RECIPE_STAMP_PATH}"))
}

fn prepare_mount_point(path: &str) -> Result<()> {
    crate::files::ensure_directory(Path::new(path), false)
        .with_context(|| format!("creating mount point {path}"))
}

/// Restricts ptrace to process descendants (Yama scope 1).
/// Without this, same-uid processes could inspect each other's memory.
fn restrict_ptrace() {
    const PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";
    if let Err(e) = fs::write(PATH, "1\n") {
        eprintln!("terra: warning: could not restrict ptrace ({PATH}): {e}");
    }
}

fn mount_share(s: &Share) -> Result<()> {
    prepare_mount_point(&s.guest)?;
    let flags = if s.readonly {
        MountFlags::RDONLY
    } else {
        MountFlags::empty()
    };
    mount(
        Some(&s.tag),
        &s.guest,
        Some("virtiofs"),
        flags | MountFlags::NOSUID | MountFlags::NODEV,
    )?;
    Ok(())
}

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[allow(unsafe_code)]
fn setup_env(plan: &Plan) {
    let home = terra_protocol::WORKLOAD_HOME;
    // SAFETY: no other thread touches the environment yet.
    unsafe {
        for (k, v) in &plan.env {
            if k.is_empty() || k.contains(['=', '\0']) || v.contains('\0') {
                eprintln!("terra: warning: skipping invalid env key `{k}`");
                continue;
            }
            std::env::set_var(k, v);
        }
        std::env::set_var("PATH", DEFAULT_PATH);
        std::env::set_var("HOME", home);
        std::env::set_var("XDG_RUNTIME_DIR", workload_runtime_dir());
        std::env::set_var("TERM", "xterm-256color");
    }
    let name = b"terrarium";
    let _ = rustix::system::sethostname(name);
}

fn setup_net(net: &Net) -> Result<()> {
    run_ip(&["link", "set", "lo", "up"])?;
    run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", net.guest_ip, net.prefix),
        "dev",
        "eth0",
    ])?;
    run_ip(&["link", "set", "eth0", "up"])?;
    run_ip(&["route", "add", "default", "via", &net.gateway.to_string()])?;
    fs::write("/etc/resolv.conf", format!("nameserver {}\n", net.dns))
        .context("writing /etc/resolv.conf")
}

fn run_ip(args: &[&str]) -> Result<()> {
    let mut command = Command::new("ip");
    command.args(args);
    let (_child, pidfd) = crate::reap::spawn_owned(|| command.spawn()).context("running ip")?;
    let status = crate::reap::wait_owned(&pidfd).context("waiting for ip")?;
    if !status.success() {
        bail!("ip {args:?} failed ({status})");
    }
    Ok(())
}

const DOAS_CONF: &str = "/etc/doas.conf";

/// Drop-in directory for doas rules; persistent files here must be cleaned up on boot.
const DOAS_DIR: &str = "/etc/doas.d";

fn setup_sudo(as_root: bool, commands: &[String]) -> Result<()> {
    use std::fmt::Write as _;
    if as_root {
        return Ok(());
    }
    match fs::remove_dir_all(DOAS_DIR) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context(format!("removing {DOAS_DIR}")),
    }
    fs::create_dir_all(DOAS_DIR).with_context(|| format!("creating {DOAS_DIR}"))?;
    let mut policy =
        String::from("# Generated by terra from the profile's `sudo:` - edits are overwritten.\n");
    for cmd in commands {
        if cmd.contains(['\n', '#']) {
            eprintln!("terra: warning: skipping invalid sudo `{cmd}`");
            continue;
        }
        let _ = writeln!(policy, "permit nopass {WORKLOAD_ID} cmd {cmd}");
    }
    fs::write(DOAS_CONF, policy).with_context(|| format!("writing {DOAS_CONF}"))?;
    // doas refuses a policy file writable by others.
    fs::set_permissions(DOAS_CONF, std::fs::Permissions::from_mode(0o640))
        .with_context(|| format!("securing {DOAS_CONF}"))?;
    Ok(())
}

fn workload_runtime_dir() -> String {
    format!("/run/user/{WORKLOAD_ID}")
}

fn setup_user(as_root: bool) -> Result<()> {
    if as_root {
        return Ok(());
    }
    let entry = format!("{WORKLOAD_USER_NAME}:");
    if !fs::read_to_string("/etc/passwd").is_ok_and(|p| p.lines().any(|l| l.starts_with(&entry))) {
        let workload_id = WORKLOAD_ID.to_string();
        run_quiet_command("addgroup", &["-g", &workload_id, WORKLOAD_USER_NAME]);
        run_quiet_command(
            "adduser",
            &[
                "-D",
                "-u",
                &workload_id,
                "-G",
                WORKLOAD_USER_NAME,
                WORKLOAD_USER_NAME,
            ],
        );
    }
    setup_subordinate_ids("/etc/subuid")?;
    setup_subordinate_ids("/etc/subgid")?;
    setup_rootless_container_config()?;
    let runtime_dir = workload_runtime_dir();
    fs::create_dir_all(&runtime_dir).with_context(|| format!("creating {runtime_dir}"))?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        &runtime_dir,
        Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
        Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
    )?;
    Ok(())
}

fn setup_rootless_container_config() -> Result<()> {
    if !Path::new("/usr/bin/podman").exists() {
        return Ok(());
    }
    let config_dir = format!("{}/.config/containers", terra_protocol::WORKLOAD_HOME);
    crate::files::ensure_directory(Path::new(&config_dir), true)?;
    let config = format!("{config_dir}/containers.conf");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config)
    {
        Ok(mut file) => {
            file.write_all(b"[engine]\ncgroup_manager = \"cgroupfs\"\n")?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error).with_context(|| format!("creating {config}")),
    }?;
    rustix::fs::chown(
        &config,
        Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
        Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
    )?;
    Ok(())
}

fn setup_subordinate_ids(path: &str) -> Result<()> {
    let entry = format!("{WORKLOAD_USER_NAME}:{SUBORDINATE_ID_START}:{SUBORDINATE_ID_COUNT}");
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {path}")),
    };
    if contents
        .lines()
        .all(|line| !line.starts_with(&format!("{WORKLOAD_USER_NAME}:")))
    {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?;
        if !contents.is_empty() && !contents.ends_with('\n') {
            writeln!(file)?;
        }
        writeln!(file, "{entry}")?;
    }
    Ok(())
}

fn run_quiet_command(cmd: &str, args: &[&str]) {
    use std::os::unix::process::CommandExt as _;

    let mut command = Command::new(cmd);
    command
        .args(args)
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = match crate::reap::spawn_owned(|| command.spawn()) {
        Ok((mut child, child_pidfd)) => wait_with_timeout(&mut child, &child_pidfd, HOOK_TIMEOUT),
        Err(error) => Err(error),
    };
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "terra: warning: `{cmd}` exited {s} - the {WORKLOAD_USER_NAME} user may be missing"
        ),
        Err(e) => eprintln!("terra: warning: could not run `{cmd}`: {e}"),
    }
}

// ---- the workload, the daemons, and the graceful stop ----------------------

/// Descendants can retain output pipes or the PTY after their parent exits.
pub(crate) const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);

struct SessionPty {
    session: Arc<Session>,
    pts: Pts,
    drained: std::sync::mpsc::Receiver<()>,
}

fn start_session(
    plan: &Plan,
    control: &File,
    port: VsockListener,
    startup: Arc<crate::vsock::StartupGate>,
) -> Result<SessionPty> {
    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(pty_process::Size::new(DEFAULT_ROWS, DEFAULT_COLS))?;

    let master: OwnedFd = pty.into();
    let reader = master.try_clone()?;
    let input_file = std::fs::File::from(master);
    let master_fd = input_file.as_raw_fd();
    let input: Sink = Arc::new(Mutex::new(input_file));
    let session = Session::new(input);

    let (initial_session, connected) = plan
        .await_initial_session
        .then(|| std::sync::mpsc::sync_channel(1))
        .map_or((None, None), |(sender, receiver)| {
            (Some(sender), Some(receiver))
        });
    crate::vsock::serve_agent_port(
        &session,
        port,
        master_fd,
        plan.root,
        initial_session,
        startup,
    );
    if let Some(connected) = connected {
        wait_for_initial_session(&connected, control)?;
    }

    let (drained_tx, drained) = std::sync::mpsc::channel();
    let out_session = session.clone();
    std::thread::spawn(move || {
        let _drained_tx = drained_tx;
        crate::exec::pump_copy(std::fs::File::from(reader), |chunk| {
            out_session.feed_output(chunk);
            true
        });
    });
    Ok(SessionPty {
        session,
        pts,
        drained,
    })
}

/// Run the plan's daemons and workload after the attached session is ready.
#[allow(unsafe_code)]
fn run_workload(
    plan: &Plan,
    control: &File,
    pts: Pts,
    drained: &std::sync::mpsc::Receiver<()>,
    session: Arc<Session>,
    stop_grace: Duration,
) -> Result<(i32, Arc<Session>, crate::daemon::Daemons)> {
    let Some((cmd, args)) = plan.workload.split_first() else {
        bail!("empty workload argv");
    };
    let daemon_output = File::from(pts.as_fd().try_clone_to_owned()?);
    let daemons = crate::daemon::spawn_all(&plan.daemons, plan.root, Some(&daemon_output))?;
    drop(daemon_output);

    let mut command = PtyCommand::new(cmd).args(args);
    if !plan.root {
        // SAFETY: the post-fork hook only changes identity with async-signal-safe syscalls.
        command = unsafe { command.pre_exec(drop_privileges) };
    }
    let (_child, child_pidfd) = match crate::reap::spawn_owned(|| command.spawn(pts)) {
        Ok(child) => child,
        Err(error) => {
            daemons.stop(stop_grace);
            return Err(error.into());
        }
    };

    let exited = Arc::new(AtomicBool::new(false));
    let control = control
        .try_clone()
        .context("cloning the control connection")?;
    let stop_exited = exited.clone();
    let stop_pidfd = child_pidfd.try_clone()?;
    std::thread::spawn(move || stop_gracefully(control, stop_pidfd, stop_exited, stop_grace));

    let code = crate::exec::wait_for_exit_code(&child_pidfd);
    exited.store(true, Ordering::SeqCst);
    let _ = drained.recv_timeout(OUTPUT_DRAIN_GRACE);
    Ok((code, session, daemons))
}

fn wait_for_initial_session(
    connected: &std::sync::mpsc::Receiver<()>,
    control: &File,
) -> Result<()> {
    const WAIT: Duration = Duration::from_secs(30);
    let flags = rustix::fs::fcntl_getfl(control).context("reading control socket flags")?;
    rustix::fs::fcntl_setfl(control, flags | rustix::fs::OFlags::NONBLOCK)
        .context("making the control socket nonblocking")?;
    let deadline = std::time::Instant::now() + WAIT;
    let mut byte = [0];
    let mut clock = None;
    let result = loop {
        if clock.is_none() {
            match connected.try_recv() {
                Ok(()) => break Ok(()),
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    break Err(anyhow::anyhow!("the foreground session listener stopped"));
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
        }
        let bytes = clock
            .as_mut()
            .map_or(&mut byte[..], |clock: &mut ClockFrame| {
                &mut clock.bytes[clock.len..]
            });
        match (&*control).read(bytes) {
            Ok(0) => break Err(anyhow::anyhow!("the host closed the control connection")),
            Ok(_) if clock.is_none() && byte[0] == STOP_SIGNAL => {
                break Err(anyhow::anyhow!(
                    "the host stopped the box before its foreground session connected"
                ));
            }
            Ok(_) if clock.is_none() && byte[0] == CLOCK_SYNC => {
                clock = Some(ClockFrame::new());
            }
            Ok(count) if clock.is_some() => {
                let Some(frame) = clock.as_mut() else {
                    break Err(anyhow::anyhow!("missing clock frame"));
                };
                frame.len += count;
                if frame.len == CLOCK_SYNC_BYTES {
                    let (seconds, nanoseconds) = match frame.decode() {
                        Ok(clock) => clock,
                        Err(error) => break Err(error),
                    };
                    if let Err(error) = synchronize_clock(seconds, nanoseconds, false) {
                        break Err(error);
                    }
                    clock = None;
                }
            }
            Ok(_) => {
                break Err(anyhow::anyhow!(
                    "invalid control command before foreground session"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => break Err(error.into()),
        }
        if std::time::Instant::now() >= deadline {
            break Err(anyhow::anyhow!(
                "the foreground session did not connect within 30 seconds"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    rustix::fs::fcntl_setfl(control, flags).context("restoring control socket flags")?;
    result
}

/// Spawns `cmd` on a PTY, dropping the slave end on return so the master EOFs on process exit.
#[allow(unsafe_code)]
pub(crate) fn spawn_on_pty(
    cmd: &str,
    args: &[String],
    rows: u16,
    cols: u16,
    as_root: bool,
    home_env: Option<&str>,
) -> Result<(Pty, std::process::Child, crate::reap::OwnedPidfd)> {
    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(pty_process::Size::new(
        rows.clamp(MIN_ROWS, MAX_ROWS),
        cols.clamp(MIN_COLS, MAX_COLS),
    ))?;
    let mut command = PtyCommand::new(cmd).args(args);
    if let Some(home_env) = home_env {
        command = command.env("HOME", home_env);
    }
    if !as_root {
        // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
        // id-setting syscalls.
        command = unsafe { command.pre_exec(drop_privileges) };
    }
    let (child, child_pidfd) = crate::reap::spawn_owned(|| command.spawn(pts))?;
    Ok((pty, child, child_pidfd))
}

/// Drops to the workload user post-fork. Setting gid before uid preserves privilege to set uid.
pub fn drop_privileges() -> std::io::Result<()> {
    rustix::thread::set_thread_groups(&[]).map_err(std::io::Error::from)?;
    rustix::thread::set_thread_gid(rustix::process::Gid::from_raw(WORKLOAD_ID))
        .map_err(std::io::Error::from)?;
    rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(WORKLOAD_ID))
        .map_err(std::io::Error::from)?;
    Ok(())
}

const STOP_POLL: Duration = Duration::from_millis(50);

/// Stops the workload on stop byte or host disconnect, escalating to SIGKILL after grace.
/// Signaling through a pidfd avoids PID recycling races with subsequent processes.
fn stop_gracefully(
    mut control: File,
    workload: OwnedFd,
    exited: Arc<AtomicBool>,
    stop_grace: Duration,
) {
    let mut byte = [0u8; 1];
    loop {
        match control.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == STOP_SIGNAL => break,
            Ok(_) if byte[0] == CLOCK_SYNC => {
                if let Err(error) = read_clock_update(&mut control) {
                    eprintln!("terra-agent: clock update failed ({error:#})");
                }
            }
            Ok(_) => eprintln!("terra-agent: ignored invalid control command"),
            // EINTR is retried; treating errors as stops would prematurely terminate the workload.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                eprintln!("terra-agent: the control connection failed ({e}) - stopping");
                break;
            }
        }
    }
    let _ = rustix::process::pidfd_send_signal(&workload, rustix::process::Signal::TERM);
    let deadline = std::time::Instant::now() + stop_grace;
    while std::time::Instant::now() < deadline && !exited.load(Ordering::SeqCst) {
        std::thread::sleep(STOP_POLL);
    }
    if !exited.load(Ordering::SeqCst) {
        eprintln!(
            "terra-agent: workload ignored SIGTERM after {}s - killing it",
            stop_grace.as_secs()
        );
        let _ = rustix::process::pidfd_send_signal(&workload, rustix::process::Signal::KILL);
    }
    drop(workload);
    drop(exited);
}

const HOOK_TIMEOUT: Duration = Duration::from_mins(5);

fn wait_with_timeout(
    child: &mut std::process::Child,
    child_pidfd: &crate::reap::OwnedPidfd,
    timeout: Duration,
) -> std::io::Result<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match rustix::process::waitid(
            rustix::process::WaitId::PidFd(child_pidfd.as_fd()),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        ) {
            Ok(Some(_)) | Err(rustix::io::Errno::CHILD) => break,
            Ok(None) => {}
            Err(error) => return Err(error.into()),
        }
        if std::time::Instant::now() >= deadline {
            crate::reap::kill_owned_process_group(
                child_pidfd,
                rustix::process::Pid::from_child(child),
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    crate::reap::wait_owned(child_pidfd)
}

fn run_hook(
    sh_cmd_line: &str,
    timeout: Option<Duration>,
    diagnostic: Option<&Diagnostics>,
    session: Option<&Arc<Session>>,
) -> Result<()> {
    use std::os::unix::process::CommandExt as _;

    let mut command = Command::new("sh");
    command.arg("-c").arg(sh_cmd_line).process_group(0);
    if diagnostic.is_some() || session.is_some() {
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
    }
    let (mut child, child_pidfd) = crate::reap::spawn_owned(|| command.spawn())
        .with_context(|| format!("spawning hook `{sh_cmd_line}`"))?;
    let pumps = (diagnostic.is_some() || session.is_some()).then(|| {
        let active = Arc::new(AtomicBool::new(true));
        HookOutput {
            pumps: [
                pump_hook_output(
                    child.stdout.take(),
                    diagnostic.cloned(),
                    session.cloned(),
                    active.clone(),
                ),
                pump_hook_output(
                    child.stderr.take(),
                    diagnostic.cloned(),
                    session.cloned(),
                    active.clone(),
                ),
            ],
            active,
        }
    });
    let status = match timeout {
        Some(timeout) => wait_with_timeout(&mut child, &child_pidfd, timeout)?,
        None => crate::reap::wait_owned(&child_pidfd)?,
    };
    if let Some(pumps) = pumps {
        drain_hook_output(pumps);
    }
    if !status.success() {
        bail!("hook `{sh_cmd_line}` failed ({status})");
    }
    Ok(())
}

struct HookOutput {
    active: Arc<AtomicBool>,
    pumps: [std::thread::JoinHandle<()>; 2],
}

fn pump_hook_output<R: Read + AsFd + Send + 'static>(
    stream: Option<R>,
    diagnostic: Option<Diagnostics>,
    session: Option<Arc<Session>>,
    active: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let Some(mut stream) = stream else {
            return;
        };
        let Ok(flags) = rustix::fs::fcntl_getfl(&stream) else {
            return;
        };
        if rustix::fs::fcntl_setfl(&stream, flags | rustix::fs::OFlags::NONBLOCK).is_err() {
            return;
        }
        let mut bytes = [0; DIAGNOSTIC_CHUNK_BYTES];
        let mut previous_cr = false;
        loop {
            if !active.load(Ordering::SeqCst) {
                return;
            }
            match stream.read(&mut bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Ok(0) | Err(_) => return,
                Ok(len) => {
                    let bytes = &bytes[..len];
                    if let Some(session) = &session {
                        let mut terminal_bytes = Vec::with_capacity(bytes.len());
                        for byte in bytes {
                            if *byte == b'\n' && !previous_cr {
                                terminal_bytes.push(b'\r');
                            }
                            terminal_bytes.push(*byte);
                            previous_cr = *byte == b'\r';
                        }
                        session.feed_output(&terminal_bytes);
                    }
                    if let Some(diagnostic) = &diagnostic {
                        diagnostic.record(bytes);
                    }
                }
            }
        }
    })
}

fn drain_hook_output(output: HookOutput) {
    let HookOutput { active, pumps } = output;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    for pump in pumps {
        while !pump.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if pump.is_finished() {
            let _ = pump.join();
        }
    }
    active.store(false, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::term::session::ClientConn;
    use std::os::fd::{AsFd, BorrowedFd};

    struct InterruptedThenData {
        fd: File,
        bytes: Option<Vec<u8>>,
        interrupted: bool,
    }

    impl Read for InterruptedThenData {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            let Some(bytes) = self.bytes.take() else {
                return Ok(0);
            };
            buf[..bytes.len()].copy_from_slice(&bytes);
            Ok(bytes.len())
        }
    }

    impl AsFd for InterruptedThenData {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    #[test]
    fn hook_output_retries_an_interrupted_read() {
        let path = crate::create_scratch_path("init", "interrupted-hook-output");
        let _ = fs::remove_file(&path);
        let diagnostics = Diagnostics::new(File::create(&path).unwrap());
        let stream = InterruptedThenData {
            fd: File::open("/dev/null").unwrap(),
            bytes: Some(b"hook output\n".to_vec()),
            interrupted: false,
        };
        let active = Arc::new(AtomicBool::new(true));
        pump_hook_output(Some(stream), Some(diagnostics.clone()), None, active)
            .join()
            .unwrap();
        diagnostics.finish();

        let mut output = File::open(&path).unwrap();
        assert_eq!(
            terra_protocol::read_frame(&mut output).unwrap(),
            Some(LifecycleEvent::Diagnostic {
                bytes: b"hook output\n".to_vec()
            })
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn an_empty_on_create_needs_no_bake_stamp() {
        assert!(ensure_baked(&[]).is_ok());
    }

    #[test]
    fn subordinate_ids_append_to_a_file_without_a_trailing_newline() {
        let path = crate::create_scratch_path("init", "subordinate-ids");
        fs::write(&path, "other:200000:65536").unwrap();
        setup_subordinate_ids(path.to_str().unwrap()).unwrap();
        setup_subordinate_ids(path.to_str().unwrap()).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "other:200000:65536\nterri:100000:65536\n"
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_fragmented_clock_frame_waits_for_its_payload() {
        let mut bytes = [0; CLOCK_SYNC_BYTES];
        bytes[0] = CLOCK_SYNC;
        bytes[1..9].copy_from_slice(&12_i64.to_le_bytes());
        bytes[9..].copy_from_slice(&34_u32.to_le_bytes());
        let mut clock = ClockFrame::new();
        clock.bytes[1..5].copy_from_slice(&bytes[1..5]);
        clock.len = 5;
        assert!(clock.decode().is_err());
        clock.bytes[5..].copy_from_slice(&bytes[5..]);
        clock.len = CLOCK_SYNC_BYTES;
        assert_eq!(clock.decode().unwrap(), (12, 34));
    }

    #[test]
    fn exit_report_is_framed_before_shutdown() {
        let mut agent = Vec::new();
        write_exit_report(&mut agent, LifecycleProtocol::Legacy, 23).expect("report writes");
        let mut host = std::io::Cursor::new(agent);
        assert_eq!(
            terra_protocol::read_frame::<i32>(&mut host).expect("report reads"),
            Some(23)
        );
    }

    #[test]
    fn events_exit_report_and_diagnostic_are_framed() {
        let mut agent = Vec::new();
        write_diagnostic(&mut agent, b"hook output").expect("diagnostic writes");
        write_exit_report(&mut agent, LifecycleProtocol::EventsV1, 23).expect("report writes");
        let mut host = std::io::Cursor::new(agent);
        assert_eq!(
            terra_protocol::read_frame(&mut host).expect("diagnostic reads"),
            Some(LifecycleEvent::Diagnostic {
                bytes: b"hook output".to_vec()
            })
        );
        assert_eq!(
            terra_protocol::read_frame(&mut host).expect("exit reads"),
            Some(LifecycleEvent::Exit { code: 23 })
        );
    }

    #[test]
    fn diagnostic_flood_does_not_block_hook_completion() {
        let (sender, _receiver) = mpsc::sync_channel(1);
        sender.send(vec![b'x']).expect("queue fills");
        let (_done, finished) = mpsc::sync_channel(1);
        let diagnostic = Diagnostics {
            sender,
            finished: Arc::new(Mutex::new(finished)),
        };
        run_hook(
            "dd if=/dev/zero bs=4096 count=512 2>/dev/null",
            Some(Duration::from_secs(2)),
            Some(&diagnostic),
            None,
        )
        .expect("hook exits despite a full diagnostic queue");
    }

    #[test]
    fn diagnostics_finish_flushes_a_queued_line() {
        let path = crate::create_scratch_path("init", "diagnostics");
        let _ = fs::remove_file(&path);
        let diagnostic = Diagnostics::new(File::create(&path).unwrap());
        diagnostic.record(b"queued diagnostic");
        diagnostic.finish();

        let mut output = File::open(&path).unwrap();
        assert_eq!(
            terra_protocol::read_frame(&mut output).unwrap(),
            Some(LifecycleEvent::Diagnostic {
                bytes: b"queued diagnostic".to_vec()
            })
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn diagnostics_finish_bounds_a_stalled_sink() {
        use std::os::unix::net::UnixStream;

        let (stream, _peer) = UnixStream::pair().unwrap();
        let diagnostic = Diagnostics::new(File::from(std::os::fd::OwnedFd::from(stream)));
        let bytes = vec![b'x'; DIAGNOSTIC_CHUNK_BYTES];
        let fill_until = std::time::Instant::now() + Duration::from_millis(100);
        while std::time::Instant::now() < fill_until {
            diagnostic.record(&bytes);
            std::thread::yield_now();
        }
        let start = std::time::Instant::now();
        diagnostic.finish();
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    fn hook_session() -> (Arc<Session>, std::os::unix::net::UnixStream) {
        use std::os::unix::net::UnixStream;

        let input: Sink = Arc::new(Mutex::new(Vec::new()));
        let session = Session::new(input);
        let (host, guest) = UnixStream::pair().unwrap();
        let client = ClientConn::from_vsock(File::from(std::os::fd::OwnedFd::from(guest))).unwrap();
        let _ = session.attach_client(&client);
        host.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut host = host;
        let _ = terra_protocol::read_frame::<terra_protocol::AgentOutput>(&mut host).unwrap();
        (session, host)
    }

    #[test]
    fn a_start_hook_reaches_the_session_before_it_finishes() {
        let (session, mut host) = hook_session();
        let running = std::thread::spawn({
            let session = session.clone();
            move || {
                run_hook(
                    "printf 'start\\n'; sleep 1; printf 'stop\\n' >&2",
                    None,
                    None,
                    Some(&session),
                )
            }
        });

        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(terra_protocol::AgentOutput::Out(b"start\r\n".to_vec()))
        );
        assert!(
            !running.is_finished(),
            "the hook finished before its first output arrived"
        );
        running.join().unwrap().unwrap();
        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(terra_protocol::AgentOutput::Out(b"stop\r\n".to_vec()))
        );
    }

    #[test]
    fn a_failing_stop_hook_leaves_its_stderr_in_the_session() {
        let (session, mut host) = hook_session();
        let error = run_hook(
            "printf 'stopping\\n' >&2; exit 7",
            None,
            None,
            Some(&session),
        )
        .unwrap_err();
        assert!(error.to_string().contains("failed"), "{error}");
        assert_eq!(
            terra_protocol::read_frame(&mut host).unwrap(),
            Some(terra_protocol::AgentOutput::Out(b"stopping\r\n".to_vec()))
        );
    }

    #[test]
    fn a_hook_descendant_cannot_hold_shutdown_on_its_output_pipe() {
        let (session, _host) = hook_session();
        let start = std::time::Instant::now();
        run_hook("sleep 3 & printf done", None, None, Some(&session)).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "hook output drain took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn a_symlinked_mount_point_is_supported() {
        let real = crate::create_scratch_path("init", "mp-real");
        let link = crate::create_scratch_path("init", "mp-link");
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_file(&link);
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        prepare_mount_point(&link.to_string_lossy()).unwrap();
        prepare_mount_point(&link.join("src").to_string_lossy()).unwrap();
        assert!(real.join("src").is_dir());

        assert!(prepare_mount_point(&real.to_string_lossy()).is_ok());
        let fresh = crate::create_scratch_path("init", "mp-fresh");
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
        let _ = run_hook("sleep 600", Some(Duration::from_millis(300)), None, None);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "sh_ok waited {:?} on a hook that never returns",
            start.elapsed()
        );
        let start = std::time::Instant::now();
        let _ = run_hook("true", Some(HOOK_TIMEOUT), None, None);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_timed_out_hook_kills_its_children() {
        let pid_file =
            std::env::temp_dir().join(format!("terra-hook-child-{}", std::process::id()));
        let _ = std::fs::remove_file(&pid_file);
        run_hook(
            &format!("sleep 600 & echo $! > {}; wait", pid_file.display()),
            Some(Duration::from_millis(100)),
            None,
            None,
        )
        .unwrap_err();
        let pid = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while rustix::process::test_kill_process(pid).is_ok()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(rustix::process::test_kill_process(pid).is_err());
        let _ = std::fs::remove_file(pid_file);
    }

    /// A workload willing to die, a 30s grace, and a stop byte: the stop must
    /// return as soon as it is gone, not wait the grace out - the box's
    /// shutdown is the workload's exit, not a timer.
    #[test]
    fn a_stop_ends_early_when_the_workload_takes_the_signal() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (mut host, guest) = UnixStream::pair().unwrap();
        let guest = File::from(std::os::fd::OwnedFd::from(guest));
        let (_child, pidfd) = crate::reap::spawn_owned(|| {
            Command::new("/bin/sh")
                .arg("-c")
                .arg("trap 'exit 0' TERM; while true; do sleep 1; done")
                .spawn()
        })
        .unwrap();
        let stop_pidfd = pidfd.try_clone().unwrap();
        let exited = Arc::new(AtomicBool::new(false));
        let reaped = exited.clone();
        let wait_workload = std::thread::spawn(move || {
            crate::reap::wait_owned(&pidfd).unwrap();
            reaped.store(true, Ordering::SeqCst);
        });

        let watcher = std::thread::spawn({
            let exited = exited.clone();
            move || {
                stop_gracefully(guest, stop_pidfd, exited, Duration::from_secs(30));
            }
        });
        host.write_all(&[STOP_SIGNAL]).unwrap();

        let start = std::time::Instant::now();
        let deadline = start + Duration::from_secs(10);
        while !watcher.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(watcher.is_finished(), "the stop waited the grace out");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the stop took {:?}",
            start.elapsed()
        );
        watcher.join().unwrap();
        wait_workload.join().unwrap();
        assert!(exited.load(Ordering::SeqCst));
    }

    #[test]
    fn a_stop_before_foreground_attach_does_not_start_the_workload() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let (mut host, guest) = UnixStream::pair().unwrap();
        let guest = File::from(std::os::fd::OwnedFd::from(guest));
        let (_sender, connected) = mpsc::sync_channel(1);
        host.write_all(&[STOP_SIGNAL]).unwrap();

        let error = wait_for_initial_session(&connected, &guest).unwrap_err();
        assert!(error.to_string().contains("stopped the box"), "{error}");
        assert!(
            !rustix::fs::fcntl_getfl(&guest)
                .unwrap()
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
    }
}
